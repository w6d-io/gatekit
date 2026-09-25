package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"

	"github.com/ory/oathkeeper/driver"
	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/rule"
)

// The reference side of these tests is Oathkeeper itself: the registered
// header/cookie mutators and the remote_json authorizer from v25.4.0.

func registry(t *testing.T) (*driver.RegistryMemory, *configuration.KoanfProvider) {
	t.Helper()
	c, err := configuration.NewKoanfProvider(context.Background(), nil, logrusx.New("", ""), configx.SkipValidation())
	if err != nil {
		t.Fatal(err)
	}
	c.SetForTest(t, configuration.MutatorHeaderIsEnabled, true)
	c.SetForTest(t, configuration.MutatorCookieIsEnabled, true)
	c.SetForTest(t, configuration.AuthorizerRemoteJSONIsEnabled, true)
	return driver.NewRegistryMemory().WithConfig(c).(*driver.RegistryMemory), c
}

const sampleJSON = `{
 "subject": "7f0e7c1c-4b1e-4c4e-9c1a-2d7a3b3f0001",
 "extra": {
  "identity": {"id": "7f0e7c1c-4b1e-4c4e-9c1a-2d7a3b3f0001",
   "traits": {"email": "Ada@Example.com", "name": {"first": "Ada", "last": "Lovelace"}},
   "metadata_public": {"groups": ["admins", "ops"], "quota": 1000000, "ratio": 0.5}},
  "authenticator_assurance_level": "aal2",
  "authentication_methods": [{"method": "password"}, {"method": "totp"}]
 },
 "header": {"X-Previous": "from-authorizer"},
 "matchContext": {
  "url": "https://app.example.com/orgs/acme/projects/42?view=full&x=%2F",
  "method": "PATCH",
  "header": {"X-Tenant": "acme", "Accept": ["application/json", "text/plain"]},
  "pattern": "<https?>://app.example.com/orgs/<[^/]+>/projects/<[0-9]+>"
 }
}`

// A template exercising every feature in play: fields, missing keys,
// print/printIndex, capture groups, URL/query/header access, sprig, toJson,
// ranges, conditionals and whitespace trimming.
const richTemplate = `{{ print .Subject }}|{{ .Extra.identity.traits.email | lower }}|` +
	`{{ .Extra.nope }}|{{ print .Extra.nope }}|{{ printIndex .MatchContext.RegexpCaptureGroups 1 }}|` +
	`{{ printIndex .MatchContext.RegexpCaptureGroups 9 }}|{{ .MatchContext.URL.Path }}|` +
	`{{ .MatchContext.URL.Query.Get "view" }}|{{ .MatchContext.Method }}|` +
	`{{ .MatchContext.Header.Get "x-tenant" }}|{{ .Header.Get "X-Previous" }}|` +
	`{{ .Extra.identity.metadata_public.groups | toJson }}|{{ .Extra.identity.metadata_public.quota }}|` +
	`{{ .Extra.identity.metadata_public.ratio }}|{{ range $i, $m := .Extra.authentication_methods }}{{ if $i }},{{ end }}{{ $m.method }}{{ end }}|` +
	`{{- if eq .Extra.authenticator_assurance_level "aal2" }} strong {{- end }}|` +
	`{{ .Extra.identity.traits.name | toJson | b64enc }}|{{ default "anon" .Extra.nope }}|{{ splitList "/" .MatchContext.URL.Path | last }}`

func sample(t *testing.T) Sample {
	t.Helper()
	var s Sample
	if err := json.Unmarshal([]byte(sampleJSON), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func render(t *testing.T, kind, name, tpl string) RenderResult {
	t.Helper()
	res, err := Render(RenderRequest{Kind: kind, Name: name, RuleID: "r1", Template: tpl, Sample: sample(t)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Error != "" {
		t.Fatalf("render error: %s", res.Error)
	}
	return res
}

func session(t *testing.T) *authn.AuthenticationSession {
	t.Helper()
	s, err := sample(t).Session()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSessionCaptureGroupsFromRealMatcher(t *testing.T) {
	got := session(t).MatchContext.RegexpCaptureGroups
	if strings.Join(got, ",") != "https,acme,42" {
		t.Fatalf("groups = %v", got)
	}
}

func TestRenderHeaderByteExactWithMutator(t *testing.T) {
	reg, _ := registry(t)
	m, err := reg.PipelineMutator("header")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(map[string]any{"headers": map[string]string{"X-Rich": richTemplate}})
	sess := session(t)
	if err := m.Mutate(&http.Request{Header: http.Header{}}, sess, cfg, &rule.Rule{ID: "r1"}); err != nil {
		t.Fatal(err)
	}
	want := sess.Header.Get("X-Rich")
	got := render(t, KindHeader, "X-Rich", richTemplate)
	if got.Value != want {
		t.Fatalf("gatekit and Oathkeeper differ:\n got %q\nwant %q", got.Value, want)
	}
	if got.Bytes != len(want) {
		t.Errorf("bytes = %d want %d", got.Bytes, len(want))
	}
	t.Logf("rendered: %s", want)
}

func TestRenderCookieByteExactWithMutator(t *testing.T) {
	reg, _ := registry(t)
	m, err := reg.PipelineMutator("cookie")
	if err != nil {
		t.Fatal(err)
	}
	tpl := `{{ .Extra.identity.traits.email }} {{ printIndex .MatchContext.RegexpCaptureGroups 1 }}`
	cfg, _ := json.Marshal(map[string]any{"cookies": map[string]string{"user": tpl}})
	sess := session(t)
	if err := m.Mutate(&http.Request{Header: http.Header{}}, sess, cfg, &rule.Rule{ID: "r1"}); err != nil {
		t.Fatal(err)
	}
	got := render(t, KindCookie, "user", tpl)
	if got.Wire != sess.Header.Get("Cookie") {
		t.Fatalf("cookie differs: got %q want %q", got.Wire, sess.Header.Get("Cookie"))
	}
}

func TestRenderPayloadByteExactWithRemoteJSON(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	reg, _ := registry(t)
	a, err := reg.PipelineAuthorizer("remote_json")
	if err != nil {
		t.Fatal(err)
	}
	tpl := `{"input":{"sub":{{ .Subject | toJson }},"email":{{ .Extra.identity.traits.email | toJson }},` +
		`"object":"{{ .MatchContext.URL.Path }}","action":"{{ .MatchContext.Method }}","org":"{{ printIndex .MatchContext.RegexpCaptureGroups 1 }}",` +
		`"aal":{{ .Extra.authenticator_assurance_level | toJson }},"app":"demo"}}`
	cfg, _ := json.Marshal(map[string]any{"remote": srv.URL, "payload": tpl})
	r := &http.Request{Header: http.Header{}, URL: &url.URL{}}
	r = r.WithContext(context.Background())
	if err := a.Authorize(r, session(t), cfg, &rule.Rule{ID: "r1"}); err != nil {
		t.Fatal(err)
	}
	got := render(t, KindPayload, "", tpl)
	if got.Value != string(body) {
		t.Fatalf("payload differs:\n got %s\nwant %s", got.Value, body)
	}
}

func TestRenderErrors(t *testing.T) {
	s := sample(t)
	cases := []struct{ kind, tpl, want string }{
		{KindHeader, "{{ .Subject", `error parsing headers template`},
		{KindHeader, `{{ index .Extra.missing "a" }}`, `error executing headers template`},
		{KindPayload, `{"sub": {{ .Subject }}}`, `payload is not a JSON text`},
		{KindClaims, `[1,2]`, `cannot unmarshal array`},
	}
	for _, c := range cases {
		res, err := Render(RenderRequest{Kind: c.kind, Template: c.tpl, Sample: s})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Error, c.want) {
			t.Errorf("%s %q: error %q, want %q", c.kind, c.tpl, res.Error, c.want)
		}
	}
	if _, err := Render(RenderRequest{Kind: "nope", Sample: s}); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestRenderWarnings(t *testing.T) {
	res := render(t, KindHeader, "X", `{{ env "HOME" }}{{ now | date "2006" }}`)
	if len(res.Warnings) != 2 {
		t.Errorf("warnings = %v", res.Warnings)
	}
}
