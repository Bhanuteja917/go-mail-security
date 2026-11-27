.PHONY: test lint vuln run up down

test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run

vuln:
	govulncheck ./...

up:
	docker compose up --build

down:
	docker compose down -v
