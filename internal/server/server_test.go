package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, cfg Config) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	logs := &bytes.Buffer{}
	s := New(cfg, slog.New(slog.NewJSONHandler(logs, nil)), NewMetrics())
	if err := s.SelfTest(); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, logs
}

func post(t *testing.T, ts *httptest.Server, path, body string, out any) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	req.Header.Set("X-Request-ID", "req-123")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s: %v (%s)", path, err, b)
		}
	}
	return res.StatusCode
}

func TestCompileEndpoint(t *testing.T) {
	ts, _ := newTestServer(t, Config{})
	var out struct {
		Results []struct {
			ID    string
			OK    bool
			Error string
		}
	}
	code := post(t, ts, "/compile", `{"patterns":[
	  {"id":"a","url":"<https?>://h/<.*>","methods":["GET"]},
	  {"id":"b","url":"https://h/<**>","methods":["GET"]}]}`, &out)
	if code != 200 || len(out.Results) != 2 || !out.Results[0].OK || out.Results[1].OK || out.Results[1].Error == "" {
		t.Fatalf("%d %+v", code, out)
	}
	if code := post(t, ts, "/compile", `{"strategy":"nope","patterns":[]}`, nil); code != 400 {
		t.Errorf("bad strategy: %d", code)
	}
}

func TestOverlapEndpoint(t *testing.T) {
	ts, _ := newTestServer(t, Config{})
	var out struct {
		Overlaps []struct{ A, B, Method, ExampleURL string }
		Checked  int
		Method   string
	}
	code := post(t, ts, "/overlap", `{"rules":[
	  {"id":"site","match":{"url":"<https?>://h/<.*>","methods":["GET"]}},
	  {"id":"api","match":{"url":"https://h/api/<.*>","methods":["GET"]}},
	  {"id":"other","match":{"url":"https://o/api/<.*>","methods":["GET"]}}],
	  "probes":[{"method":"GET","url":"https://h/api/x"}], "hosts":["h"]}`, &out)
	if code != 200 || len(out.Overlaps) != 1 || out.Method != "probe" || out.Checked == 0 {
		t.Fatalf("%d %+v", code, out)
	}
	if o := out.Overlaps[0]; o.A != "site" || o.B != "api" || o.Method != "GET" {
		t.Errorf("%+v", o)
	}
}

func TestMatchEndpoint(t *testing.T) {
	ts, _ := newTestServer(t, Config{})
	rules := `[{"id":"site","match":{"url":"<https?>://h/<.*>","methods":["GET"]}},
	           {"id":"api","match":{"url":"https://h/api/<.*>","methods":["GET"]}}]`
	for url, want := range map[string]string{"https://h/api/x": "multiple", "http://h/": "one", "https://x/": "none"} {
		var out struct {
			Matched []string
			Verdict string
		}
		code := post(t, ts, "/match", `{"method":"GET","url":"`+url+`","rules":`+rules+`}`, &out)
		if code != 200 || out.Verdict != want {
			t.Errorf("%s: %d %+v want %s", url, code, out, want)
		}
	}
	if code := post(t, ts, "/match", `{"method":"GET","url":"/relative","rules":[]}`, nil); code != 400 {
		t.Errorf("relative url: %d", code)
	}
}

func TestRenderEndpoint(t *testing.T) {
	ts, _ := newTestServer(t, Config{})
	var out struct {
		Value string
		Bytes int
		Error string
	}
	code := post(t, ts, "/render", `{"kind":"header","template":"{{ .Extra.identity.traits.email }}:{{ printIndex .MatchContext.RegexpCaptureGroups 1 }}",
	  "sample":{"subject":"u1","extra":{"identity":{"traits":{"email":"a@b.c"}}},
	  "matchContext":{"url":"https://h/orgs/acme","method":"GET","pattern":"<https?>://h/orgs/<[^/]+>"}}}`, &out)
	if code != 200 || out.Value != "a@b.c:acme" || out.Bytes != 10 || out.Error != "" {
		t.Fatalf("%d %+v", code, out)
	}
	code = post(t, ts, "/render", `{"kind":"payload","template":"{not json","sample":{}}`, &out)
	if code != 200 || !strings.Contains(out.Error, "payload is not a JSON text") {
		t.Fatalf("%d %+v", code, out)
	}
}

func TestLimitsAndValidation(t *testing.T) {
	ts, _ := newTestServer(t, Config{MaxBodyBytes: 64})
	if code := post(t, ts, "/compile", `{"patterns":[{"id":"`+strings.Repeat("a", 200)+`","url":"x"}]}`, nil); code != 413 {
		t.Errorf("oversized body: %d", code)
	}
	if code := post(t, ts, "/compile", `{"patterns":[],"unknown":1}`, nil); code != 400 {
		t.Errorf("unknown field: %d", code)
	}
	res, _ := http.Get(ts.URL + "/compile")
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /compile: %d", res.StatusCode)
	}
}

func TestProbesAndLogs(t *testing.T) {
	ts, logs := newTestServer(t, Config{})
	for _, p := range []string{"/healthz", "/readyz"} {
		res, err := http.Get(ts.URL + p)
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("%s: %v %v", p, err, res)
		}
	}
	post(t, ts, "/compile", `{"patterns":[]}`, nil)
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &line); err != nil {
		t.Fatalf("log is not one JSON line: %q", logs.String())
	}
	if line["log_type"] != "access" || line["request_id"] != "req-123" || line["route"] != "/compile" {
		t.Errorf("log = %v", line)
	}
}

func TestNotReadyBeforeSelfTest(t *testing.T) {
	s := New(Config{}, slog.New(slog.NewJSONHandler(io.Discard, nil)), NewMetrics())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz before self-test: %d", rec.Code)
	}
}

func TestMetricsHandler(t *testing.T) {
	m := NewMetrics()
	s := New(Config{}, slog.New(slog.NewJSONHandler(io.Discard, nil)), m)
	_ = s.SelfTest()
	s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `gatekit_http_requests_total{code="200",route="/healthz"} 1`) {
		t.Errorf("metrics missing request counter:\n%s", rec.Body.String())
	}
}
