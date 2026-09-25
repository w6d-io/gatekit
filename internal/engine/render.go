package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"golang.org/x/net/http/httpguts"

	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/rule"
	"github.com/ory/oathkeeper/x"
)

// Template kinds and the Oathkeeper handler whose rendering each one mirrors.
const (
	KindHeader  = "header"  // mutator header, authorizer remote(_json).headers
	KindCookie  = "cookie"  // mutator cookie
	KindPayload = "payload" // authorizer remote_json payload
	KindClaims  = "claims"  // mutator id_token claims
)

// Header accepts {"X-A": "v"} or {"X-A": ["v1","v2"]}.
type Header http.Header

func (h *Header) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	out := http.Header{}
	for k, v := range raw {
		var one string
		if err := json.Unmarshal(v, &one); err == nil {
			out.Add(k, one)
			continue
		}
		var many []string
		if err := json.Unmarshal(v, &many); err != nil {
			return fmt.Errorf("header %q: want a string or a list of strings", k)
		}
		for _, m := range many {
			out.Add(k, m)
		}
	}
	*h = Header(out)
	return nil
}

// SampleMatchContext describes the request. When RegexpCaptureGroups is nil
// and Pattern is set, groups are extracted by the real matcher.
type SampleMatchContext struct {
	URL                 string   `json:"url"`
	Method              string   `json:"method"`
	Header              Header   `json:"header"`
	RegexpCaptureGroups []string `json:"regexpCaptureGroups"`
	Pattern             string   `json:"pattern"`
	Strategy            string   `json:"strategy"`
}

// Sample is the AuthenticationSession a template is rendered against.
type Sample struct {
	Subject      string                 `json:"subject"`
	Extra        map[string]interface{} `json:"extra"`
	Header       Header                 `json:"header"`
	MatchContext SampleMatchContext     `json:"matchContext"`
}

// RenderRequest is the /render request.
type RenderRequest struct {
	Kind     string `json:"kind"`
	Template string `json:"template"`
	Name     string `json:"name"`   // header or cookie name (optional)
	RuleID   string `json:"ruleId"` // only used in error messages, as Oathkeeper does
	Sample   Sample `json:"sample"`
}

// RenderResult is the /render response. Value is the exact template output;
// Wire is what reaches the upstream when it differs (cookie encoding).
type RenderResult struct {
	Value    string   `json:"value"`
	Bytes    int      `json:"bytes"`
	Wire     string   `json:"wire,omitempty"`
	Error    string   `json:"error,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// Session builds the authn.AuthenticationSession that Oathkeeper's request
// handler would hand to mutators and authorizers.
func (s Sample) Session() (*authn.AuthenticationSession, error) {
	sess := &authn.AuthenticationSession{Subject: s.Subject, Extra: s.Extra, Header: http.Header(s.Header)}
	mc := s.MatchContext
	sess.MatchContext.Method = mc.Method
	sess.MatchContext.Header = http.Header(mc.Header)
	sess.MatchContext.RegexpCaptureGroups = mc.RegexpCaptureGroups
	if mc.URL == "" {
		return sess, nil
	}
	u, err := ParseRequestURL(mc.URL)
	if err != nil {
		return nil, err
	}
	sess.MatchContext.URL = u
	if mc.RegexpCaptureGroups == nil && mc.Pattern != "" {
		strategy, err := Strategy(mc.Strategy)
		if err != nil {
			return nil, err
		}
		r := &rule.Rule{Match: &rule.Match{URL: mc.Pattern}}
		groups, err := r.ExtractRegexGroups(strategy, u)
		if err != nil {
			return nil, fmt.Errorf("sample url does not match pattern: %w", err)
		}
		sess.MatchContext.RegexpCaptureGroups = groups
	}
	return sess, nil
}

// Render executes a template exactly like the matching Oathkeeper handler:
// x.NewTemplate (text/template, missingkey=zero, print/printIndex, sprig),
// New(id).Parse, Execute(session), then the handler's own post-processing.
func Render(req RenderRequest) (RenderResult, error) {
	sess, err := req.Sample.Session()
	if err != nil {
		return RenderResult{}, err
	}
	rid := req.RuleID
	name := req.Name
	var root, id string
	switch req.Kind {
	case KindHeader:
		root, id = "header", fmt.Sprintf("%s:%s", rid, name)
	case KindCookie:
		root, id = "cookie", fmt.Sprintf("%s:%s", rid, name)
	case KindPayload:
		root, id = "remote_json", "payload"
	case KindClaims:
		root, id = "id_token", "claims"
	default:
		return RenderResult{}, fmt.Errorf("unknown kind %q (want header, cookie, payload or claims)", req.Kind)
	}

	res := RenderResult{Warnings: templateWarnings(req.Template)}
	t, err := x.NewTemplate(root).New(id).Parse(req.Template)
	if err != nil {
		res.Error = wrapErr(req.Kind, "parsing", req.Template, rid, err).Error()
		return res, nil
	}
	var b bytes.Buffer
	if err := t.Execute(&b, sess); err != nil {
		res.Error = wrapErr(req.Kind, "executing", req.Template, rid, err).Error()
		return res, nil
	}
	res.Value, res.Bytes = b.String(), b.Len()
	if strings.Contains(res.Value, "<no value>") {
		res.Warnings = append(res.Warnings, `output contains "<no value>": a map key is missing (missingkey=zero does not apply to map[string]interface{}); guard it with "print" or "default"`)
	}

	switch req.Kind {
	case KindHeader:
		if !httpguts.ValidHeaderFieldValue(res.Value) {
			res.Warnings = append(res.Warnings, "value contains bytes Go's HTTP client refuses to send (CR, LF or control characters): the upstream call fails with 502")
		}
		if res.Bytes > 8<<10 {
			res.Warnings = append(res.Warnings, "value is larger than 8 KiB: ingress-nginx and many upstreams reject headers this large")
		}
	case KindCookie:
		// Same encoding as mutator_cookie: http.Request.AddCookie.
		r := http.Request{Header: http.Header{}}
		r.AddCookie(&http.Cookie{Name: name, Value: res.Value})
		res.Wire = r.Header.Get("Cookie")
	case KindPayload:
		var j json.RawMessage
		if err := json.Unmarshal(b.Bytes(), &j); err != nil {
			res.Error = errors.Wrap(err, "payload is not a JSON text").Error()
		}
	case KindClaims:
		claims := jwt.MapClaims{}
		if err := json.Unmarshal(b.Bytes(), &claims); err != nil {
			res.Error = err.Error()
		}
	}
	return res, nil
}

// wrapErr reproduces each handler's error wording.
func wrapErr(kind, phase, tpl, rid string, err error) error {
	switch kind {
	case KindHeader:
		return errors.Wrapf(err, `error %s headers template "%s" in rule "%s"`, phase, tpl, rid)
	case KindCookie:
		return errors.Wrapf(err, `error %s cookie template "%s" in rule "%s"`, phase, tpl, rid)
	case KindClaims:
		return errors.Wrapf(err, `error %s claims template in rule "%s"`, phase, rid)
	}
	return err
}

// templateWarnings flags functions whose output depends on the process that
// renders the template rather than on the session.
func templateWarnings(tpl string) []string {
	var w []string
	for _, fn := range []string{"env", "expandenv"} {
		if strings.Contains(tpl, fn+" ") {
			w = append(w, fn+" reads the environment of the process rendering it: Oathkeeper's at runtime, gatekit's in this preview")
		}
	}
	for _, fn := range []string{"now", "uuidv4", "randAlpha", "randNumeric", "randAlphaNum", "randAscii"} {
		if strings.Contains(tpl, fn) {
			w = append(w, fn+" is not deterministic: the preview differs from every real request")
		}
	}
	return w
}
