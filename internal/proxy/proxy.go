// Package proxy wires the guard engine into an HTTP reverse proxy that
// forwards to an upstream OpenAI-compatible endpoint.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/arthurpanhku/gorial/internal/audit"
	"github.com/arthurpanhku/gorial/internal/config"
	"github.com/arthurpanhku/gorial/internal/guard"
)

// Server is the guardrail reverse proxy.
type Server struct {
	cfg    *config.Config
	engine *guard.Engine
	proxy  *httputil.ReverseProxy
	logger *audit.Logger
}

// New builds a Server from a validated config.
func New(cfg *config.Config) (*Server, error) {
	target, err := url.Parse(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("parse target url: %w", err)
	}

	guards, err := buildGuards(cfg)
	if err != nil {
		return nil, err
	}

	logger, err := audit.New(cfg.Log)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	origDirector := rp.Director
	rp.Director = func(r *http.Request) {
		origDirector(r)
		// Route the upstream vhost/TLS correctly...
		r.Host = target.Host
		// ...and ask for an uncompressed response so guards can inspect it.
		r.Header.Del("Accept-Encoding")
	}

	s := &Server{
		cfg:    cfg,
		engine: guard.NewEngine(guards),
		proxy:  rp,
		logger: logger,
	}
	rp.ModifyResponse = s.inspectResponse
	return s, nil
}

// Handler returns the http.Handler that applies inbound guards then proxies.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	return mux
}

// ListenAndServe starts the proxy on the configured listen address.
func (s *Server) ListenAndServe() error {
	return http.ListenAndServe(s.cfg.Listen, s.Handler())
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"gorial: cannot read request body"}`, http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	dec := s.engine.Evaluate(r.Context(), &guard.Content{Direction: guard.Inbound, Body: body})

	s.logger.Log(audit.Entry{
		Time:      start,
		Direction: string(guard.Inbound),
		Method:    r.Method,
		Path:      r.URL.Path,
		Blocked:   dec.Blocked,
		Findings:  findingNames(dec.Findings),
		LatencyMS: msSince(start),
	})

	if dec.Blocked {
		writeBlocked(w, dec.Findings)
		return
	}

	// Forward the (possibly redacted) body.
	r.Body = io.NopCloser(bytes.NewReader(dec.Body))
	r.ContentLength = int64(len(dec.Body))
	r.Header.Del("Content-Length")

	s.proxy.ServeHTTP(w, r)
}

// inspectResponse runs outbound guards over the upstream response. Streaming
// (SSE) responses are passed through untouched because redaction needs the
// full body; that is a documented v1 limitation.
func (s *Server) inspectResponse(resp *http.Response) error {
	if isStreaming(resp) {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	dec := s.engine.Evaluate(context.Background(), &guard.Content{Direction: guard.Outbound, Body: body})

	out := dec.Body
	if dec.Blocked {
		out = []byte(`{"error":"gorial: response blocked by guardrail"}`)
		resp.StatusCode = http.StatusForbidden
		resp.Status = http.StatusText(http.StatusForbidden)
		resp.Header.Set("Content-Type", "application/json")
	}

	path := ""
	if resp.Request != nil {
		path = resp.Request.URL.Path
	}
	s.logger.Log(audit.Entry{
		Time:      time.Now(),
		Direction: string(guard.Outbound),
		Path:      path,
		Status:    resp.StatusCode,
		Blocked:   dec.Blocked,
		Findings:  findingNames(dec.Findings),
	})

	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}

func isStreaming(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")
}

func writeBlocked(w http.ResponseWriter, findings []guard.Finding) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":    "request blocked by gorial guardrail",
		"findings": findingNames(findings),
	})
}

func findingNames(findings []guard.Finding) []string {
	names := make([]string, 0, len(findings))
	for _, f := range findings {
		names = append(names, fmt.Sprintf("%s(%s):%s", f.Guard, f.Action, f.Reason))
	}
	return names
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}
