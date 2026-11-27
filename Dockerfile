# syntax=docker/dockerfile:1
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/threat-intel-api ./cmd/threat-intel-api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/threat-intel-api /threat-intel-api
EXPOSE 8080
ENTRYPOINT ["/threat-intel-api"]
