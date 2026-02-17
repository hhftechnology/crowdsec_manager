# Stage 1: Build frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /app/ui
RUN corepack enable && corepack prepare pnpm@latest --activate
COPY ui/package.json ui/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY ui/ .
RUN pnpm build

# Stage 2: Build backend
FROM golang:1.24-alpine AS backend-builder
RUN apk add --no-cache gcc musl-dev sqlite-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=frontend-builder /app/ui/dist ./ui/dist
ENV CGO_ENABLED=1
RUN go build -o bin/crowdsec-manager ./cmd/server

# Stage 3: Runtime
FROM alpine:3.21
RUN apk add --no-cache ca-certificates sqlite-libs tzdata
WORKDIR /app
COPY --from=backend-builder /app/bin/crowdsec-manager .
COPY --from=backend-builder /app/ui/dist ./ui/dist

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN mkdir -p /app/data && chown -R appuser:appgroup /app/data

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/api/health/containers || exit 1

USER appuser
ENTRYPOINT ["/app/crowdsec-manager"]
