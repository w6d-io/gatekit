// Command gatekit serves Oathkeeper v25.4.0's matcher and template engine
// over HTTP so callers can check rules before they reach the gateway.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/w6d-io/gatekit/internal/server"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "gatekit")
	if err := run(log); err != nil {
		log.Error("exit", "log_type", "app", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	// gatekit never calls out; make any accidental outbound HTTP fail loudly.
	http.DefaultTransport = &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("gatekit: outbound network is disabled")
	}}

	maxBody, _ := strconv.ParseInt(env("GATEKIT_MAX_BODY_BYTES", "1048576"), 10, 64)
	timeout, err := time.ParseDuration(env("GATEKIT_REQUEST_TIMEOUT", "10s"))
	if err != nil {
		return err
	}
	metrics := server.NewMetrics()
	srv := server.New(server.Config{MaxBodyBytes: maxBody, RequestTimeout: timeout}, log, metrics)
	if err := srv.SelfTest(); err != nil {
		return err
	}

	api := &http.Server{
		Addr:              env("GATEKIT_LISTEN", ":8080"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      timeout + 5*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	mon := &http.Server{
		Addr:              env("GATEKIT_METRICS_LISTEN", ":9090"),
		Handler:           metrics.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	errc := make(chan error, 2)
	for _, s := range []*http.Server{api, mon} {
		go func(s *http.Server) {
			log.Info("listening", "log_type", "app", "addr", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(s)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down", "log_type", "app")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = mon.Shutdown(sctx)
	return api.Shutdown(sctx)
}
