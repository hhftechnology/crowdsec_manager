# Multi-stage Dockerfile for CrowdSec Manager

# Stage 1: Build frontend
FROM node:20-alpine AS frontend-builder

WORKDIR /app/web

# Copy package files
COPY web/package*.json ./

# Install dependencies
RUN npm ci --legacy-peer-deps

# Copy frontend source
COPY web/ ./

# Build frontend
RUN npm run build

# Stage 2: Build Go backend
FROM golang:1.23-alpine AS backend-builder

WORKDIR /app

# Install build dependencies (CGO required for go-sqlite3)
RUN apk add --no-cache git gcc musl-dev sqlite-dev

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY cmd/ cmd/
COPY internal/ internal/

# Build binary (CGO_ENABLED=1 required for go-sqlite3)
RUN CGO_ENABLED=1 GOOS=linux go build -o crowdsec-manager ./cmd/server

# Stage 3: Final runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata curl

WORKDIR /app

# Copy binary from builder
COPY --from=backend-builder /app/crowdsec-manager .

# Copy frontend build from frontend-builder
COPY --from=frontend-builder /app/web/dist ./web/dist

# Create necessary directories with proper permissions
RUN mkdir -p /app/backups /app/logs /app/config /app/data

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Create default user (1000:1000)
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser && \
    chown -R appuser:appuser /app

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Install su-exec for safe privilege dropping
RUN apk add --no-cache su-exec

# Don't set USER - let entrypoint handle it
# This allows the entrypoint to fix permissions before dropping privileges

# Use entrypoint script
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["./crowdsec-manager"]
