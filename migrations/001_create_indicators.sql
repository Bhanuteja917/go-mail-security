-- Known-bad indicators collected from public threat feeds.
CREATE TABLE IF NOT EXISTS indicators (
    id         BIGSERIAL PRIMARY KEY,
    kind       TEXT        NOT NULL CHECK (kind IN ('url', 'domain', 'ip')),
    value      TEXT        NOT NULL,
    source     TEXT        NOT NULL,
    threat     TEXT        NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, value, source)
);

CREATE INDEX IF NOT EXISTS indicators_lookup_idx ON indicators (kind, value);
