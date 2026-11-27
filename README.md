# go-mail-security

Two Go services that work together as a small email-security platform:

| Service | What it does | Status |
| --- | --- | --- |
| `threat-intel-api` | Answers "is this URL, domain or IP known to be bad?" from public threat feeds, over REST (gRPC later) | In progress (week 1) |
| `email-phishscan` | Scans a raw email and returns a risk score with reasons; uses `threat-intel-api` | Planned |

## Run threat-intel-api locally

```sh
docker compose up --build
curl 'localhost:8080/healthz'
curl 'localhost:8080/v1/lookup?domain=example.com'
```

Lookup parameters: exactly one of `url`, `domain` or `ip`. The response has `verdict`
(`malicious` or `unknown`) and the matching feed entries.

## Develop

```sh
make test   # go test -race ./...
make lint   # go vet + golangci-lint
```

Configuration is by environment variable: `DATABASE_URL` (required), `HTTP_ADDR` (default `:8080`),
`LOG_LEVEL` (default `info`), `SHUTDOWN_TIMEOUT` (default `15s`).

## Layout

```
cmd/threat-intel-api/   entrypoint
internal/config/        env config
internal/intel/         domain types and normalization
internal/httpapi/       REST handlers and middleware
internal/store/         Postgres access
migrations/             SQL schema
```
