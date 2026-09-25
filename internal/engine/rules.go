// Package engine wraps Oathkeeper v25.4.0's own matcher and template engine.
// Every verdict (compile, match, overlap) comes from rule.Rule.IsMatching and
// every rendered value from x.NewTemplate; nothing here re-implements them.
package engine

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/rule"
)

// Verdicts returned by Match, mirroring RepositoryMemory.Match outcomes.
const (
	VerdictOne      = "one"      // exactly one rule: Oathkeeper serves the request
	VerdictNone     = "none"     // 404 "Requested url does not match any rules"
	VerdictMultiple = "multiple" // 500 "Expected exactly one rule but found multiple rules"
	VerdictError    = "error"    // a rule errored (compile/timeout): Oathkeeper aborts the match
)

// probeURL is only used to force compilation; the result of the match is ignored.
var probeURL = &url.URL{Scheme: "http", Host: "gatekit.invalid", Path: "/"}

// Strategy validates and converts a strategy name. Empty means regexp,
// Oathkeeper's default.
func Strategy(s string) (configuration.MatchingStrategy, error) {
	switch configuration.MatchingStrategy(s) {
	case "", configuration.Regexp:
		return configuration.Regexp, nil
	case configuration.Glob:
		return configuration.Glob, nil
	}
	return "", fmt.Errorf("unknown matching strategy %q (want regexp or glob)", s)
}

// RuleError reports a rule the real matcher refused.
type RuleError struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

// ParseRules decodes rules with Oathkeeper's own rule.Rule unmarshaller
// (including its version migration), so full rule documents are accepted.
func ParseRules(raw []json.RawMessage) ([]*rule.Rule, error) {
	rules := make([]*rule.Rule, 0, len(raw))
	for i, r := range raw {
		var rl rule.Rule
		if err := json.Unmarshal(r, &rl); err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		if rl.Match == nil {
			return nil, fmt.Errorf("rules[%d] (%s): match is required", i, rl.ID)
		}
		rules = append(rules, &rl)
	}
	return rules, nil
}

// compileErr compiles a pattern through rule.Rule.IsMatching and returns the
// matcher's error, if any.
func compileErr(pattern string, strategy configuration.MatchingStrategy) error {
	r := &rule.Rule{Match: &rule.Match{URL: pattern, Methods: []string{"GET"}}}
	_, err := r.IsMatching(strategy, "GET", probeURL, rule.ProtocolHTTP)
	return err
}

// Pattern is one entry of a /compile request.
type Pattern struct {
	ID      string   `json:"id"`
	URL     string   `json:"url"`
	Methods []string `json:"methods"`
}

// CompileResult is one entry of a /compile response.
type CompileResult struct {
	ID       string   `json:"id"`
	OK       bool     `json:"ok"`
	Error    string   `json:"error,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// Compile checks every pattern with the real matching engine.
func Compile(patterns []Pattern, strategy configuration.MatchingStrategy) []CompileResult {
	out := make([]CompileResult, 0, len(patterns))
	for _, p := range patterns {
		res := CompileResult{ID: p.ID, OK: true}
		if p.URL == "" {
			res.OK, res.Error = false, "match.url is empty"
		} else if err := compileErr(p.URL, strategy); err != nil {
			res.OK, res.Error = false, err.Error()
		}
		if p.Methods != nil && len(p.Methods) == 0 {
			res.Warnings = append(res.Warnings, "methods is empty: the rule never matches")
		}
		if strategy == configuration.Regexp && res.OK {
			res.Warnings = append(res.Warnings, regexpWarnings(p.URL)...)
		}
		out = append(out, res)
	}
	return out
}

// regexpWarnings flags well-known pitfalls (oathkeeper-spec §13.3) that
// compile fine but rarely do what the author meant.
func regexpWarnings(pattern string) []string {
	var w []string
	if strings.Contains(pattern, "<(s?)>") {
		w = append(w, "http<(s?)> adds two capture groups; prefer <https?>")
	}
	if strings.HasSuffix(pattern, "/<.*>") {
		w = append(w, "trailing /<.*> does not match the path without the slash; use <(/.*)?>")
	}
	return w
}

// MatchResult is the /match response.
type MatchResult struct {
	Matched       []string    `json:"matched"`
	Verdict       string      `json:"verdict"`
	CaptureGroups []string    `json:"captureGroups,omitempty"`
	Errors        []RuleError `json:"errors,omitempty"`
}

// Match runs one request against a rule set exactly as
// RepositoryMemory.Match does: every rule is tested, no precedence.
func Match(method string, u *url.URL, rules []*rule.Rule, strategy configuration.MatchingStrategy) MatchResult {
	res := MatchResult{Matched: []string{}}
	var hit *rule.Rule
	for _, r := range rules {
		ok, err := r.IsMatching(strategy, method, u, rule.ProtocolHTTP)
		if err != nil {
			res.Errors = append(res.Errors, RuleError{ID: r.ID, Error: err.Error()})
			continue
		}
		if ok {
			res.Matched = append(res.Matched, r.ID)
			hit = r
		}
	}
	switch {
	case len(res.Errors) > 0:
		res.Verdict = VerdictError
	case len(res.Matched) == 0:
		res.Verdict = VerdictNone
	case len(res.Matched) == 1:
		res.Verdict = VerdictOne
		if g, err := hit.ExtractRegexGroups(strategy, u); err == nil {
			res.CaptureGroups = g
		}
	default:
		res.Verdict = VerdictMultiple
	}
	return res
}

// ParseRequestURL parses a request URL the way Oathkeeper sees it: scheme,
// host (with port) and decoded path; the query never takes part in matching.
func ParseRequestURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("url %q must be absolute (scheme://host/path)", raw)
	}
	return u, nil
}
