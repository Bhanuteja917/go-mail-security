package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bhanuteja917/go-mail-security/internal/intel"
)

type fakeStore struct {
	matches map[string][]intel.Match
	err     error
	pingErr error
}

func (f fakeStore) Lookup(_ context.Context, kind intel.Kind, value string) ([]intel.Match, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.matches[string(kind)+":"+value], nil
}
func (f fakeStore) Ping(context.Context) error { return f.pingErr }

func newHandler(s fakeStore) http.Handler {
	return New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestLookup(t *testing.T) {
	hit := []intel.Match{{Source: "urlhaus", Threat: "malware_download", FirstSeen: time.Unix(1, 0), LastSeen: time.Unix(2, 0)}}
	store := fakeStore{matches: map[string][]intel.Match{"domain:evil.com": hit}}

	tests := []struct {
		name        string
		store       fakeStore
		query       string
		wantStatus  int
		wantVerdict string
	}{
		{"known bad domain, case-insensitive", store, "domain=EVIL.com", 200, "malicious"},
		{"unknown domain", store, "domain=fine.org", 200, "unknown"},
		{"no parameter", store, "", 400, ""},
		{"two parameters", store, "domain=a.com&ip=1.1.1.1", 400, ""},
		{"invalid ip", store, "ip=nope", 400, ""},
		{"store failure", fakeStore{err: errors.New("boom")}, "domain=evil.com", 500, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newHandler(tt.store).ServeHTTP(rec, httptest.NewRequest("GET", "/v1/lookup?"+tt.query, nil))
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantVerdict != "" {
				var got lookupResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if got.Verdict != tt.wantVerdict {
					t.Fatalf("verdict = %q, want %q", got.Verdict, tt.wantVerdict)
				}
			}
		})
	}
}

func TestHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	newHandler(fakeStore{}).ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("healthz = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	newHandler(fakeStore{pingErr: errors.New("down")}).ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with db down = %d, want 503", rec.Code)
	}
}
