package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/rule"
)

func rules(t *testing.T, js string) []*rule.Rule {
	t.Helper()
	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(js), &raw); err != nil {
		t.Fatal(err)
	}
	rs, err := ParseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestCompile(t *testing.T) {
	res := Compile([]Pattern{
		{ID: "ok", URL: "<https?>://app.example.com/api/<(?!health).*>", Methods: []string{"GET"}},
		{ID: "bad-regex", URL: "https://app.example.com/<(unclosed>"},
		{ID: "glob-under-regexp", URL: "https://app.example.com/<**>"},
		{ID: "unbalanced", URL: "https://app.example.com/<.*"},
		{ID: "empty", URL: ""},
		{ID: "never", URL: "https://app.example.com/", Methods: []string{}},
	}, configuration.Regexp)

	want := map[string]bool{"ok": true, "bad-regex": false, "glob-under-regexp": false, "unbalanced": false, "empty": false, "never": true}
	for _, r := range res {
		if r.OK != want[r.ID] {
			t.Errorf("%s: ok=%v want %v (error %q)", r.ID, r.OK, want[r.ID], r.Error)
		}
		if !r.OK && r.Error == "" {
			t.Errorf("%s: rejected without an error message", r.ID)
		}
	}
	if len(res[5].Warnings) == 0 {
		t.Errorf("empty methods should warn")
	}
}

func TestCompileGlob(t *testing.T) {
	res := Compile([]Pattern{{ID: "g", URL: "https://app.example.com/<**>"}}, configuration.Glob)
	if !res[0].OK {
		t.Fatalf("<**> is valid glob: %s", res[0].Error)
	}
}

func TestMatchVerdicts(t *testing.T) {
	rs := rules(t, `[
	 {"id":"site","match":{"url":"<https?>://app.example.com/<.*>","methods":["GET","POST"]}},
	 {"id":"api","match":{"url":"https://app.example.com/api/<.*>","methods":["get"]}},
	 {"id":"other","match":{"url":"https://other.example.com/<.*>","methods":["GET"]}}
	]`)
	cases := []struct {
		method, url, verdict string
		n                    int
	}{
		{"GET", "https://app.example.com/api/items?q=1", VerdictMultiple, 2},
		{"POST", "https://app.example.com/api/items", VerdictOne, 1},
		{"GET", "https://other.example.com/x", VerdictOne, 1},
		{"GET", "https://nobody.example.com/", VerdictNone, 0},
		{"GET", "https://App.example.com/", VerdictNone, 0}, // host is case-sensitive
	}
	for _, c := range cases {
		u, err := ParseRequestURL(c.url)
		if err != nil {
			t.Fatal(err)
		}
		got := Match(c.method, u, rs, configuration.Regexp)
		if got.Verdict != c.verdict || len(got.Matched) != c.n {
			t.Errorf("%s %s: got %v %v, want %s", c.method, c.url, got.Verdict, got.Matched, c.verdict)
		}
	}

	u, _ := ParseRequestURL("http://app.example.com/home")
	got := Match("GET", u, rs[:1], configuration.Regexp)
	if strings.Join(got.CaptureGroups, ",") != "http,home" {
		t.Errorf("capture groups = %v", got.CaptureGroups)
	}
}

func TestMatchErrorVerdict(t *testing.T) {
	rs := rules(t, `[{"id":"bad","match":{"url":"https://h/<(>","methods":["GET"]}}]`)
	u, _ := ParseRequestURL("https://h/x")
	if got := Match("GET", u, rs, configuration.Regexp); got.Verdict != VerdictError || len(got.Errors) != 1 {
		t.Errorf("got %+v", got)
	}
}

func overlaps(t *testing.T, js string, probes []ProbeRequest) OverlapResult {
	t.Helper()
	res, err := FindOverlaps(context.Background(), rules(t, js), probes, nil, configuration.Regexp)
	if err != nil {
		t.Fatal(err)
	}
	if res.Method != "probe" {
		t.Errorf("method = %q", res.Method)
	}
	return res
}

func TestOverlapDetectedWithExample(t *testing.T) {
	res := overlaps(t, `[
	 {"id":"site","match":{"url":"<https?>://app.example.com/<.*>","methods":["GET","POST"]}},
	 {"id":"api","match":{"url":"https://app.example.com/api/<[a-z]+>/<[0-9]+>","methods":["GET","DELETE"]}}
	]`, nil)
	if len(res.Overlaps) != 1 {
		t.Fatalf("overlaps = %+v", res.Overlaps)
	}
	o := res.Overlaps[0]
	if o.A != "site" || o.B != "api" || o.Method != "GET" {
		t.Errorf("overlap = %+v", o)
	}
	// The example is real: Oathkeeper would answer 500 for it.
	u, err := ParseRequestURL(o.ExampleURL)
	if err != nil {
		t.Fatal(err)
	}
	if m := Match("GET", u, rules(t, `[
	 {"id":"site","match":{"url":"<https?>://app.example.com/<.*>","methods":["GET","POST"]}},
	 {"id":"api","match":{"url":"https://app.example.com/api/<[a-z]+>/<[0-9]+>","methods":["GET","DELETE"]}}
	]`), configuration.Regexp); m.Verdict != VerdictMultiple {
		t.Errorf("example %s: verdict %s", o.ExampleURL, m.Verdict)
	}
	if res.Checked == 0 || res.Probes == 0 {
		t.Errorf("nothing checked: %+v", res)
	}
}

func TestNegativeLookaheadCarveOut(t *testing.T) {
	res := overlaps(t, `[
	 {"id":"api","match":{"url":"https://app.example.com/api/<(?!health).*>","methods":["GET"]}},
	 {"id":"health","match":{"url":"https://app.example.com/api/health","methods":["GET"]}}
	]`, nil)
	if len(res.Overlaps) != 0 {
		t.Fatalf("carve-out reported as overlap: %+v", res.Overlaps)
	}

	// Without the carve-out the same pair overlaps.
	res = overlaps(t, `[
	 {"id":"api","match":{"url":"https://app.example.com/api/<.*>","methods":["GET"]}},
	 {"id":"health","match":{"url":"https://app.example.com/api/health","methods":["GET"]}}
	]`, nil)
	if len(res.Overlaps) != 1 || res.Overlaps[0].ExampleURL != "https://app.example.com/api/health" {
		t.Fatalf("overlaps = %+v", res.Overlaps)
	}
}

func TestOverlapEnumerationCarveOut(t *testing.T) {
	// The Site pattern style: one gate enumerates, the catch-all excludes.
	res := overlaps(t, `[
	 {"id":"gate-api","match":{"url":"<https?>://app.example.com/<(api|admin)(/.*)?>","methods":["GET","POST"]}},
	 {"id":"gate-web","match":{"url":"<https?>://app.example.com/<(?!(api|admin)(/|$)).*>","methods":["GET","POST"]}}
	]`, nil)
	if len(res.Overlaps) != 0 {
		t.Fatalf("overlaps = %+v", res.Overlaps)
	}
}

func TestOverlapHostAndMethodAware(t *testing.T) {
	res := overlaps(t, `[
	 {"id":"a","match":{"url":"https://a.example.com/<.*>","methods":["GET"]}},
	 {"id":"b","match":{"url":"https://b.example.com/<.*>","methods":["GET"]}},
	 {"id":"a-preflight","match":{"url":"https://a.example.com/<.*>","methods":["OPTIONS"]}}
	]`, nil)
	if len(res.Overlaps) != 0 {
		t.Fatalf("overlaps = %+v", res.Overlaps)
	}

	// A host pattern is compared against every host.
	res = overlaps(t, `[
	 {"id":"a","match":{"url":"https://a.example.com/<.*>","methods":["GET"]}},
	 {"id":"wild","match":{"url":"https://<[a-z]+>.example.com/x","methods":["GET"]}}
	]`, nil)
	if len(res.Overlaps) != 1 || res.Overlaps[0].ExampleURL != "https://a.example.com/x" {
		t.Fatalf("overlaps = %+v", res.Overlaps)
	}
}

func TestOverlapCallerProbesAndInvalid(t *testing.T) {
	res := overlaps(t, `[
	 {"id":"a","match":{"url":"https://h/<[a-m].*>","methods":["GET"]}},
	 {"id":"b","match":{"url":"https://h/<.*z>","methods":["GET"]}},
	 {"id":"broken","match":{"url":"https://h/<(>","methods":["GET"]}}
	]`, []ProbeRequest{{Method: "get", URL: "https://h/quiz"}, {Method: "GET", URL: "https://h/abz"}})
	if len(res.Invalid) != 1 || res.Invalid[0].ID != "broken" {
		t.Errorf("invalid = %+v", res.Invalid)
	}
	found := false
	for _, o := range res.Overlaps {
		found = found || (o.A == "a" && o.B == "b")
	}
	if !found {
		t.Errorf("caller probe overlap missing: %+v", res.Overlaps)
	}
}

func TestProbeToURLRoundTrip(t *testing.T) {
	for _, s := range []string{"https://h/a/b", "https://h", "http://h:8080/x.json", "https://h/p?q=1"} {
		u, ok := probeToURL(s)
		if !ok {
			t.Fatalf("%s rejected", s)
		}
		if got := u.Scheme + "://" + u.Host + u.Path; got != strings.SplitN(s, "?", 2)[0] {
			t.Errorf("%s -> %s", s, got)
		}
	}
}

func TestHostKey(t *testing.T) {
	for p, want := range map[string]string{
		"<https?>://app.example.com/<.*>": "app.example.com",
		"https://h:8443/x":                "h:8443",
		"https://<[a-z]+>.example.com/":   "",
		"<.*>://h/":                       "",
		"https://h<.*>":                   "",
	} {
		if got := hostKey(p); got != want {
			t.Errorf("hostKey(%q) = %q want %q", p, got, want)
		}
	}
}
