package engine

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/rule"
)

// OverlapMethod names how overlaps are found, so callers never mistake a
// clean result for a proof.
const OverlapMethod = "probe"

// ProbeRequest is a caller-supplied probe.
type ProbeRequest struct {
	Method string `json:"method"`
	URL    string `json:"url"`
}

// Overlap is one pair of rules that both match the same request.
type Overlap struct {
	A          string `json:"a"`
	B          string `json:"b"`
	Method     string `json:"method"`
	ExampleURL string `json:"exampleUrl"`
}

// OverlapResult is the /overlap response.
type OverlapResult struct {
	Overlaps []Overlap   `json:"overlaps"`
	Invalid  []RuleError `json:"invalid,omitempty"`
	Checked  int         `json:"checked"`
	Probes   int         `json:"probes"`
	Method   string      `json:"method"`
}

type probe struct {
	method string // "" = every method the matched rules share
	url    string
}

// FindOverlaps generates probes from every rule (plus caller probes and hosts)
// and runs each against every rule that could serve its host, using the real
// matcher. It reports each overlapping (a, b, method) once with an example.
func FindOverlaps(ctx context.Context, rules []*rule.Rule, probes []ProbeRequest, hosts []string, strategy configuration.MatchingStrategy) (OverlapResult, error) {
	res := OverlapResult{Overlaps: []Overlap{}, Method: OverlapMethod}

	valid := make([]*rule.Rule, 0, len(rules))
	order := map[*rule.Rule]int{}
	patterns := make([]string, 0, len(rules))
	for i, r := range rules {
		if err := compileErr(r.Match.GetURL(), strategy); err != nil {
			res.Invalid = append(res.Invalid, RuleError{ID: r.ID, Error: err.Error()})
			continue
		}
		order[r] = i
		valid = append(valid, r)
		patterns = append(patterns, r.Match.GetURL())
	}

	byHost := map[string][]*rule.Rule{}
	var anyHost []*rule.Rule
	for _, r := range valid {
		if h := hostKey(r.Match.GetURL()); h != "" && strategy == configuration.Regexp {
			byHost[h] = append(byHost[h], r)
		} else {
			anyHost = append(anyHost, r)
		}
	}

	tokens := corpusTokens(patterns, hosts)
	seen := map[probe]bool{}
	var all []probe
	add := func(p probe) {
		if !seen[p] {
			seen[p] = true
			all = append(all, p)
		}
	}
	for _, p := range probes {
		add(probe{method: strings.ToUpper(p.Method), url: p.URL})
	}
	for _, p := range patterns {
		for _, u := range probesFor(p, tokens, strategy) {
			add(probe{url: u})
		}
	}
	res.Probes = len(all)

	found := map[[3]string]bool{}
	errored := map[*rule.Rule]bool{}
	for n, p := range all {
		if n%64 == 0 && ctx.Err() != nil {
			return res, ctx.Err()
		}
		u, ok := probeToURL(p.url)
		if !ok {
			continue
		}
		candidates := append(append([]*rule.Rule{}, byHost[u.Host]...), anyHost...)
		var hits []*rule.Rule
		for _, r := range candidates {
			m := p.method
			if m == "" {
				if len(r.Match.GetMethods()) == 0 {
					continue
				}
				m = r.Match.GetMethods()[0]
			}
			res.Checked++
			matched, err := r.IsMatching(strategy, m, u, rule.ProtocolHTTP)
			if err != nil {
				if !errored[r] {
					errored[r] = true
					res.Invalid = append(res.Invalid, RuleError{ID: r.ID, Error: err.Error()})
				}
				continue
			}
			if matched {
				hits = append(hits, r)
			}
		}
		sort.Slice(hits, func(i, j int) bool { return order[hits[i]] < order[hits[j]] })
		for i := 0; i < len(hits); i++ {
			for j := i + 1; j < len(hits); j++ {
				for _, m := range sharedMethods(hits[i], hits[j], p.method) {
					key := [3]string{hits[i].ID, hits[j].ID, m}
					if !found[key] {
						found[key] = true
						res.Overlaps = append(res.Overlaps, Overlap{A: hits[i].ID, B: hits[j].ID, Method: m, ExampleURL: p.url})
					}
				}
			}
		}
	}
	sort.SliceStable(res.Overlaps, func(i, j int) bool {
		a, b := res.Overlaps[i], res.Overlaps[j]
		if a.A != b.A {
			return a.A < b.A
		}
		if a.B != b.B {
			return a.B < b.B
		}
		return a.Method < b.Method
	})
	return res, nil
}

// sharedMethods lists (upper-cased) methods both rules match; Oathkeeper
// compares methods case-insensitively. A probe with a method restricts it.
func sharedMethods(a, b *rule.Rule, only string) []string {
	set := map[string]bool{}
	for _, m := range a.Match.GetMethods() {
		set[strings.ToUpper(m)] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range b.Match.GetMethods() {
		m = strings.ToUpper(m)
		if set[m] && !seen[m] && (only == "" || only == m) {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// probeToURL splits a probe so that fmt "%s://%s%s" of scheme, host and path
// (what rule.IsMatching matches against) gives back the probe verbatim.
// Caller probes go through url.Parse like real requests do.
func probeToURL(s string) (*url.URL, bool) {
	i := strings.Index(s, "://")
	if i <= 0 {
		return nil, false
	}
	rest := s[i+3:]
	host, path := rest, ""
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		host, path = rest[:j], rest[j:]
	}
	if strings.ContainsAny(s, "?#%") {
		if u, err := ParseRequestURL(s); err == nil {
			return u, true
		}
	}
	return &url.URL{Scheme: s[:i], Host: host, Path: path}, true
}
