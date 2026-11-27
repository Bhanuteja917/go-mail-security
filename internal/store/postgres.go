// Package store implements intel.Store on top of PostgreSQL.
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bhanuteja917/go-mail-security/internal/intel"
)

// Postgres is a pgx-backed intel.Store.
type Postgres struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres and verifies the connection.
func Open(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Close releases all connections.
func (p *Postgres) Close() { p.pool.Close() }

// Ping reports whether the database is reachable.
func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

// Lookup returns every feed entry for the normalized value.
func (p *Postgres) Lookup(ctx context.Context, kind intel.Kind, value string) ([]intel.Match, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT source, threat, first_seen, last_seen
		   FROM indicators
		  WHERE kind = $1 AND value = $2
		  ORDER BY last_seen DESC`, string(kind), value)
	if err != nil {
		return nil, fmt.Errorf("query indicators: %w", err)
	}
	defer rows.Close()
	var out []intel.Match
	for rows.Next() {
		var m intel.Match
		if err := rows.Scan(&m.Source, &m.Threat, &m.FirstSeen, &m.LastSeen); err != nil {
			return nil, fmt.Errorf("scan indicator: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
