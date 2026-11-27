// Package intel holds the domain types and normalization rules for indicators
// of compromise (IOCs) such as malicious URLs, domains and IP addresses.
package intel

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

// Kind is the type of an indicator.
type Kind string

const (
	KindURL    Kind = "url"
	KindDomain Kind = "domain"
	KindIP     Kind = "ip"
)

// Indicator is one known-bad value reported by a feed.
type Indicator struct {
	Kind      Kind
	Value     string // normalized, see Normalize
	Source    string // for example "urlhaus"
	Threat    string // for example "malware_download"
	FirstSeen time.Time
	LastSeen  time.Time
}

// Match is a stored indicator returned by a lookup.
type Match struct {
	Source    string    `json:"source"`
	Threat    string    `json:"threat,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Store is what the API needs from the database layer.
type Store interface {
	Lookup(ctx context.Context, kind Kind, value string) ([]Match, error)
	Ping(ctx context.Context) error
}

// ErrInvalid is returned when a value cannot be normalized for its kind.
var ErrInvalid = errors.New("invalid indicator")

// Normalize returns the canonical form of value for the given kind, so the same
// indicator always maps to the same database key.
func Normalize(kind Kind, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrInvalid
	}
	switch kind {
	case KindDomain:
		d := strings.TrimSuffix(strings.ToLower(value), ".")
		if d == "" || strings.ContainsAny(d, "/ :@") || !strings.Contains(d, ".") {
			return "", ErrInvalid
		}
		return d, nil
	case KindIP:
		ip := net.ParseIP(value)
		if ip == nil {
			return "", ErrInvalid
		}
		return ip.String(), nil
	case KindURL:
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return "", ErrInvalid
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.Fragment = ""
		return u.String(), nil
	default:
		return "", ErrInvalid
	}
}
