// Package proxy wires the guard engine into an HTTP reverse proxy that
// forwards to an upstream OpenAI-compatible endpoint.
package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	requestID := requestID(r)
	w.Header().Set("X-Gorial-Request-ID", requestID)
	r.Header.Set("X-Gorial-Request-ID", requestID)

	body, tooLarge, err := readLimited(r.Body, s.cfg.Limits.MaxRequestBytes)
	if err != nil {
		http.Error(w, `{"error":"gorial: cannot read request body"}`, http.StatusBadRequest)
		return
	}
	if tooLarge {
		s.logger.Log(audit.Entry{
			Time:         start,
			EventID:      newID(),
			RequestID:    requestID,
			Direction:    string(guard.Inbound),
			Method:       r.Method,
			Path:         r.URL.Path,
			Decision:     sizeDecision(s.cfg.Limits.OnRequestTooLarge),
			Blocked:      s.cfg.Limits.OnRequestTooLarge == "block",
			Bypassed:     s.cfg.Limits.OnRequestTooLarge != "block",
			BypassReason: "request_too_large",
			LatencyMS:    msSince(start),
		})
		if s.cfg.Limits.OnRequestTooLarge == "block" {
			_ = r.Body.Close()
			writeError(w, http.StatusRequestEntityTooLarge, "request blocked by gorial size limit", requestID, nil)
			return
		}
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
		r.ContentLength = -1
		r.Header.Del("Content-Length")
		s.proxy.ServeHTTP(w, r)
		return
	}
	_ = r.Body.Close()

	ctx, cancel := s.guardContext(r.Context())
	defer cancel()
	dec := s.engine.Evaluate(ctx, &guard.Content{Direction: guard.Inbound, Body: body})

	s.logger.Log(audit.Entry{
		Time:      start,
		EventID:   newID(),
		RequestID: requestID,
		Direction: string(guard.Inbound),
		Method:    r.Method,
		Path:      r.URL.Path,
		Decision:  decisionName(dec),
		Blocked:   dec.Blocked,
		Redacted:  !dec.Blocked && !bytes.Equal(body, dec.Body),
		Findings:  findingNames(dec.Findings),
		LatencyMS: msSince(start),
	})

	if dec.Blocked {
		writeBlocked(w, requestID, dec.Findings)
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
	requestID := ""
	if resp.Request != nil {
		requestID = resp.Request.Header.Get("X-Gorial-Request-ID")
	}
	if requestID == "" {
		requestID = newID()
	}
	resp.Header.Set("X-Gorial-Request-ID", requestID)

	if isStreaming(resp) {
		s.logOutbound(resp, audit.Entry{
			Time:         time.Now(),
			EventID:      newID(),
			RequestID:    requestID,
			Decision:     "bypass",
			Bypassed:     true,
			BypassReason: "streaming_pass_through",
		})
		return nil
	}

	start := time.Now()
	body, tooLarge, err := readLimited(resp.Body, s.cfg.Limits.MaxResponseBytes)
	if err != nil {
		return err
	}
	if tooLarge {
		s.logOutbound(resp, audit.Entry{
			Time:         start,
			EventID:      newID(),
			RequestID:    requestID,
			Decision:     sizeDecision(s.cfg.Limits.OnResponseTooLarge),
			Blocked:      s.cfg.Limits.OnResponseTooLarge == "block",
			Bypassed:     s.cfg.Limits.OnResponseTooLarge != "block",
			BypassReason: "response_too_large",
			LatencyMS:    msSince(start),
		})
		if s.cfg.Limits.OnResponseTooLarge == "block" {
			_ = resp.Body.Close()
			out := []byte(`{"error":"gorial: response blocked by size limit"}`)
			resp.StatusCode = http.StatusBadGateway
			resp.Status = http.StatusText(http.StatusBadGateway)
			resp.Header.Set("Content-Type", "application/json")
			resp.Body = io.NopCloser(bytes.NewReader(out))
			resp.ContentLength = int64(len(out))
			resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
			return nil
		}
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		return nil
	}
	_ = resp.Body.Close()

	ctx, cancel := s.guardContext(context.Background())
	defer cancel()
	dec := s.engine.Evaluate(ctx, &guard.Content{Direction: guard.Outbound, Body: body})

	out := dec.Body
	if dec.Blocked {
		out = []byte(`{"error":"gorial: response blocked by guardrail"}`)
		resp.StatusCode = http.StatusForbidden
		resp.Status = http.StatusText(http.StatusForbidden)
		resp.Header.Set("Content-Type", "application/json")
	}

	s.logOutbound(resp, audit.Entry{
		Time:      start,
		EventID:   newID(),
		RequestID: requestID,
		Decision:  decisionName(dec),
		Blocked:   dec.Blocked,
		Redacted:  !dec.Blocked && !bytes.Equal(body, out),
		Findings:  findingNames(dec.Findings),
		LatencyMS: msSince(start),
	})

	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}

func (s *Server) guardContext(parent context.Context) (context.Context, context.CancelFunc) {
	if s.cfg.Limits.GuardTimeoutMS <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, time.Duration(s.cfg.Limits.GuardTimeoutMS)*time.Millisecond)
}

func (s *Server) logOutbound(resp *http.Response, e audit.Entry) {
	e.Direction = string(guard.Outbound)
	e.Status = resp.StatusCode
	if resp.Request != nil {
		e.Path = resp.Request.URL.Path
	}
	s.logger.Log(e)
}

func isStreaming(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")
}

func writeBlocked(w http.ResponseWriter, requestID string, findings []guard.Finding) {
	writeError(w, http.StatusForbidden, "request blocked by gorial guardrail", requestID, findingNames(findings))
}

func writeError(w http.ResponseWriter, status int, message, requestID string, findings []string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":      message,
		"request_id": requestID,
		"findings":   findings,
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

func readLimited(r io.Reader, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		body, err := io.ReadAll(r)
		return body, false, err
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > limit {
		return body, true, nil
	}
	return body, false, nil
}

func requestID(r *http.Request) string {
	for _, header := range []string{"X-Request-ID", "X-Gorial-Request-ID"} {
		if id := strings.TrimSpace(r.Header.Get(header)); id != "" {
			return id
		}
	}
	return newID()
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func decisionName(dec guard.Decision) string {
	if dec.Blocked {
		return "block"
	}
	if len(dec.Findings) > 0 {
		return "redact"
	}
	return "allow"
}

func sizeDecision(action string) string {
	if action == "block" {
		return "block"
	}
	return "bypass"
}
