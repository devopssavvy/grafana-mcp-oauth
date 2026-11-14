# Build stage
FROM golang:1.27-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o mcp-auth-helper ./cmd/mcp-auth-helper

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/mcp-auth-helper /app/mcp-auth-helper

EXPOSE 8081 9001

USER 65534:65534

ENTRYPOINT ["/app/mcp-auth-helper"]
