# Build a single static binary, then ship it on scratch.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /gorial ./cmd/gorial

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /gorial /gorial
COPY config.example.yaml /config.yaml
EXPOSE 8080
ENTRYPOINT ["/gorial", "-config", "/config.yaml"]
