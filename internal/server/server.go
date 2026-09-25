// Package server exposes the engine over a small JSON HTTP API.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/w6d-io/gatekit/internal/engine"
)

// Config tunes limits; zero values get safe defaults.
type Config struct {
	MaxBodyBytes   int64
	RequestTimeout time.Duration
	MaxRules       int
	MaxProbes      int
}

func (c *Config) defaults() {
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 1 << 20
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 10 * time.Second
	}
	if c.MaxRules <= 0 {
		c.MaxRules = 2000
	}
	if c.MaxProbes <= 0 {
		c.MaxProbes = 5000
	}
}

// Server holds the API handlers.
type Server struct {
	cfg     Config
	log     *slog.Logger
	metrics *Metrics
	ready   atomic.Bool
}

// New builds a server; call SelfTest before serving to flip readiness.
func New(cfg Config, log *slog.Logger, m *Metrics) *Server {
	cfg.defaults()
	return &Server{cfg: cfg, log: log, metrics: m}
}

// SelfTest proves the embedded matcher and template engine work, then marks
// the server ready.
func (s *Server) SelfTest() error {
	res := engine.Compile([]engine.Pattern{
		{ID: "good", URL: "<https?>://gatekit.invalid/<(?!x).*>"},
		{ID: "bad", URL: "https://gatekit.invalid/<(>"},
	}, "")
	if !res[0].OK || res[1].OK {
		return errors.New("self-test: matcher verdicts are wrong")
	}
	r, err := engine.Render(engine.RenderRequest{Kind: engine.KindHeader, Template: "{{ print .Subject }}", Sample: engine.Sample{Subject: "ok"}})
	if err != nil || r.Value != "ok" {
		return errors.New("self-test: template engine is broken")
	}
	s.ready.Store(true)
	return nil
}

// Handler returns the API mux wrapped in logging, metrics and limits.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /compile", s.compile)
	mux.HandleFunc("POST /overlap", s.overlap)
	mux.HandleFunc("POST /match", s.match)
	mux.HandleFunc("POST /render", s.render)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	return s.middleware(mux)
}

type compileReq struct {
	Strategy string           `json:"strategy"`
	Patterns []engine.Pattern `json:"patterns"`
}

func (s *Server) compile(w http.ResponseWriter, r *http.Request) {
	var req compileReq
	if !s.decode(w, r, &req) {
		return
	}
	strategy, err := engine.Strategy(req.Strategy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Patterns) > s.cfg.MaxRules {
		writeError(w, http.StatusRequestEntityTooLarge, "too many patterns")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": engine.Compile(req.Patterns, strategy)})
}

type overlapReq struct {
	Strategy string                `json:"strategy"`
	Rules    []json.RawMessage     `json:"rules"`
	Probes   []engine.ProbeRequest `json:"probes"`
	Hosts    []string              `json:"hosts"`
}

func (s *Server) overlap(w http.ResponseWriter, r *http.Request) {
	var req overlapReq
	if !s.decode(w, r, &req) {
		return
	}
	strategy, err := engine.Strategy(req.Strategy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Rules) > s.cfg.MaxRules || len(req.Probes) > s.cfg.MaxProbes {
		writeError(w, http.StatusRequestEntityTooLarge, "too many rules or probes")
		return
	}
	rules, err := engine.ParseRules(req.Rules)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()
	res, err := engine.FindOverlaps(ctx, rules, req.Probes, req.Hosts, strategy)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "overlap check did not finish in time: "+err.Error())
		return
	}
	s.metrics.probes.Add(float64(res.Checked))
	writeJSON(w, http.StatusOK, res)
}

type matchReq struct {
	Strategy string            `json:"strategy"`
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Rules    []json.RawMessage `json:"rules"`
}

func (s *Server) match(w http.ResponseWriter, r *http.Request) {
	var req matchReq
	if !s.decode(w, r, &req) {
		return
	}
	strategy, err := engine.Strategy(req.Strategy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Method == "" {
		writeError(w, http.StatusBadRequest, "method is required")
		return
	}
	u, err := engine.ParseRequestURL(req.URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Rules) > s.cfg.MaxRules {
		writeError(w, http.StatusRequestEntityTooLarge, "too many rules")
		return
	}
	rules, err := engine.ParseRules(req.Rules)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, engine.Match(req.Method, u, rules, strategy))
}

func (s *Server) render(w http.ResponseWriter, r *http.Request) {
	var req engine.RenderRequest
	if !s.decode(w, r, &req) {
		return
	}
	res, err := engine.Render(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// decode reads a size-limited JSON body; unknown fields are refused so typos
// in a contract surface immediately.
func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
