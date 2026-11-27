// Package httpapi is the REST layer of threat-intel-api.
package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/Bhanuteja917/go-mail-security/internal/intel"
)

// New builds the HTTP handler with routes and middleware.
func New(store intel.Store, log *slog.Logger) http.Handler {
	s := &server{store: store, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /v1/lookup", s.lookup)
	return s.logRequests(mux)
}

type server struct {
	store intel.Store
	log   *slog.Logger
}

type lookupResponse struct {
	Kind      intel.Kind    `json:"kind"`
	Value     string        `json:"value"`
	Verdict   string        `json:"verdict"` // "malicious" or "unknown"
	Matches   []intel.Match `json:"matches"`
	CheckedAt time.Time     `json:"checked_at"`
}

func (s *server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		s.log.Error("readiness check failed", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "database unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// lookup answers GET /v1/lookup?url=..., ?domain=... or ?ip=... (exactly one).
func (s *server) lookup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var kind intel.Kind
	var raw string
	for _, k := range []intel.Kind{intel.KindURL, intel.KindDomain, intel.KindIP} {
		if v := q.Get(string(k)); v != "" {
			if kind != "" {
				writeError(w, http.StatusBadRequest, "provide exactly one of url, domain or ip")
				return
			}
			kind, raw = k, v
		}
	}
	if kind == "" {
		writeError(w, http.StatusBadRequest, "provide exactly one of url, domain or ip")
		return
	}
	value, err := intel.Normalize(kind, raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid "+string(kind))
		return
	}
	matches, err := s.store.Lookup(r.Context(), kind, value)
	if err != nil {
		s.log.Error("lookup failed", "kind", kind, "err", err)
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	resp := lookupResponse{Kind: kind, Value: value, Verdict: "unknown", Matches: matches, CheckedAt: time.Now().UTC()}
	if resp.Matches == nil {
		resp.Matches = []intel.Match{}
	}
	if len(matches) > 0 {
		resp.Verdict = "malicious"
	}
	writeJSON(w, http.StatusOK, resp)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
