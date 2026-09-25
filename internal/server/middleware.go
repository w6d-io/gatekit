package server

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics are served on their own port, never on the API listener.
type Metrics struct {
	reg      *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	probes   prometheus.Counter
}

// NewMetrics registers gatekit's collectors plus Go/process collectors.
func NewMetrics() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatekit_http_requests_total", Help: "API requests by route and status code.",
		}, []string{"route", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "gatekit_http_request_duration_seconds", Help: "API latency by route.",
			Buckets: []float64{.005, .01, .025, .05, .1, .15, .25, .5, 1, 2.5, 5, 10},
		}, []string{"route"}),
		probes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gatekit_overlap_evaluations_total", Help: "Probe x rule evaluations run by /overlap.",
		}),
	}
	m.reg.MustRegister(m.requests, m.duration, m.probes,
		prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	return m
}

// Handler serves /metrics.
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{}))
	return mux
}

type recorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-ID"); requestIDRe.MatchString(id) {
		return id
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var knownRoutes = map[string]bool{"/compile": true, "/overlap": true, "/match": true, "/render": true, "/healthz": true, "/readyz": true}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := requestID(r)
		w.Header().Set("X-Request-ID", id)
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		route := r.URL.Path
		if !knownRoutes[route] {
			route = "other"
		}
		elapsed := time.Since(start)
		s.metrics.requests.WithLabelValues(route, strconv.Itoa(rec.status)).Inc()
		s.metrics.duration.WithLabelValues(route).Observe(elapsed.Seconds())
		if route == "/healthz" || route == "/readyz" {
			return
		}
		s.log.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("log_type", "access"),
			slog.String("request_id", id),
			slog.String("method", r.Method),
			slog.String("route", route),
			slog.Int("status", rec.status),
			slog.Int("bytes", rec.bytes),
			slog.Float64("duration_ms", float64(elapsed.Microseconds())/1000),
		)
	})
}
