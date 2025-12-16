#!/bin/bash

# CrowdSec Manager - Docker Image Build Script
# Builds Docker images for all proxy configurations

set -e

# Configuration
REGISTRY="${REGISTRY:-crowdsec-manager}"
VERSION="${VERSION:-2.0.0}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
PUSH="${PUSH:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker buildx version &> /dev/null; then
        log_error "Docker Buildx is not available"
        exit 1
    fi
    
    # Check if buildx builder exists
    if ! docker buildx inspect multiarch &> /dev/null; then
        log_info "Creating multiarch builder..."
        docker buildx create --name multiarch --platform ${PLATFORMS} --use
    else
        docker buildx use multiarch
    fi
    
    log_success "Prerequisites check passed"
}

# Build base image
build_base_image() {
    log_info "Building base CrowdSec Manager image..."
    
    local image_name="${REGISTRY}/crowdsec-manager:${VERSION}"
    local latest_tag="${REGISTRY}/crowdsec-manager:latest"
    
    local build_args=""
    if [ "${PUSH}" = "true" ]; then
        build_args="--push"
    else
        build_args="--load"
    fi
    
    docker buildx build \
        --platform ${PLATFORMS} \
        --tag ${image_name} \
        --tag ${latest_tag} \
        --file Dockerfile \
        ${build_args} \
        .
    
    log_success "Base image built: ${image_name}"
}

# Build proxy-specific images
build_proxy_images() {
    local proxy_types=("traefik" "nginx" "caddy" "haproxy" "zoraxy" "standalone")
    
    for proxy_type in "${proxy_types[@]}"; do
        log_info "Building ${proxy_type} configuration image..."
        
        local image_name="${REGISTRY}/crowdsec-manager:${VERSION}-${proxy_type}"
        local latest_tag="${REGISTRY}/crowdsec-manager:latest-${proxy_type}"
        
        # Create temporary Dockerfile for proxy-specific image
        cat > "Dockerfile.${proxy_type}" << EOF
FROM ${REGISTRY}/crowdsec-manager:${VERSION}

# Proxy-specific metadata
LABEL proxy.type="${proxy_type}"
LABEL proxy.version="${VERSION}"

# Copy proxy-specific configuration
COPY examples/${proxy_type}/.env /app/examples/.env.${proxy_type}

# Set default proxy type
ENV PROXY_TYPE=${proxy_type}

# Proxy-specific health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD curl -f http://localhost:\${PORT:-8080}/health || exit 1
EOF
        
        local build_args=""
        if [ "${PUSH}" = "true" ]; then
            build_args="--push"
        else
            build_args="--load"
        fi
        
        docker buildx build \
            --platform ${PLATFORMS} \
            --tag ${image_name} \
            --tag ${latest_tag} \
            --file "Dockerfile.${proxy_type}" \
            ${build_args} \
            .
        
        # Clean up temporary Dockerfile
        rm -f "Dockerfile.${proxy_type}"
        
        log_success "${proxy_type} image built: ${image_name}"
    done
}

# Build development image
build_dev_image() {
    log_info "Building development image..."
    
    local image_name="${REGISTRY}/crowdsec-manager:${VERSION}-dev"
    local latest_tag="${REGISTRY}/crowdsec-manager:dev"
    
    # Create development Dockerfile
    cat > Dockerfile.dev << 'EOF'
FROM golang:1.23-alpine AS dev-base

# Install development dependencies
RUN apk add --no-cache \
    git \
    gcc \
    musl-dev \
    sqlite-dev \
    curl \
    nodejs \
    npm \
    air

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy package files
COPY web/package*.json ./web/
RUN cd web && npm ci --legacy-peer-deps

# Install air for hot reload
RUN go install github.com/cosmtrek/air@latest

# Copy source code
COPY . .

# Build frontend for development
RUN cd web && npm run build

# Expose ports
EXPOSE 8080 3000

# Development command with hot reload
CMD ["air", "-c", ".air.toml"]
EOF
    
    local build_args=""
    if [ "${PUSH}" = "true" ]; then
        build_args="--push"
    else
        build_args="--load"
    fi
    
    docker buildx build \
        --platform ${PLATFORMS} \
        --tag ${image_name} \
        --tag ${latest_tag} \
        --file Dockerfile.dev \
        ${build_args} \
        .
    
    # Clean up temporary Dockerfile
    rm -f Dockerfile.dev
    
    log_success "Development image built: ${image_name}"
}

# Build all-in-one images with proxy included
build_allinone_images() {
    local proxy_configs=(
        "traefik:traefik:latest"
        "nginx:jc21/nginx-proxy-manager:latest"
        "caddy:caddy:latest"
        "haproxy:haproxy:latest"
    )
    
    for config in "${proxy_configs[@]}"; do
        IFS=':' read -r proxy_type proxy_image proxy_tag <<< "$config"
        
        log_info "Building all-in-one ${proxy_type} image..."
        
        local image_name="${REGISTRY}/crowdsec-manager:${VERSION}-${proxy_type}-allinone"
        local latest_tag="${REGISTRY}/crowdsec-manager:latest-${proxy_type}-allinone"
        
        # Create all-in-one Dockerfile
        cat > "Dockerfile.${proxy_type}-allinone" << EOF
# Multi-stage build for all-in-one ${proxy_type} image
FROM ${REGISTRY}/crowdsec-manager:${VERSION} AS manager
FROM ${proxy_image}:${proxy_tag} AS proxy
FROM crowdsecurity/crowdsec:latest AS crowdsec

# Final all-in-one image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add \\
    ca-certificates \\
    tzdata \\
    curl \\
    supervisor \\
    bash

# Copy CrowdSec Manager
COPY --from=manager /app /app

# Copy proxy binaries (proxy-specific)
$(case $proxy_type in
    "traefik")
        echo "COPY --from=proxy /usr/local/bin/traefik /usr/local/bin/traefik"
        ;;
    "caddy")
        echo "COPY --from=proxy /usr/bin/caddy /usr/bin/caddy"
        ;;
    "haproxy")
        echo "COPY --from=proxy /usr/local/sbin/haproxy /usr/local/sbin/haproxy"
        ;;
esac)

# Copy CrowdSec
COPY --from=crowdsec /usr/local/bin/crowdsec /usr/local/bin/crowdsec
COPY --from=crowdsec /usr/local/bin/cscli /usr/local/bin/cscli

# Create supervisor configuration
RUN mkdir -p /etc/supervisor/conf.d

# Copy supervisor configuration
COPY docker/supervisor-${proxy_type}.conf /etc/supervisor/conf.d/supervisord.conf

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/config /var/log/supervisor

# Expose ports
EXPOSE 80 443 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \\
  CMD curl -f http://localhost:8080/health || exit 1

# Start supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
EOF
        
        local build_args=""
        if [ "${PUSH}" = "true" ]; then
            build_args="--push"
        else
            build_args="--load"
        fi
        
        docker buildx build \
            --platform ${PLATFORMS} \
            --tag ${image_name} \
            --tag ${latest_tag} \
            --file "Dockerfile.${proxy_type}-allinone" \
            ${build_args} \
            .
        
        # Clean up temporary Dockerfile
        rm -f "Dockerfile.${proxy_type}-allinone"
        
        log_success "All-in-one ${proxy_type} image built: ${image_name}"
    done
}

# Generate image manifest
generate_manifest() {
    log_info "Generating image manifest..."
    
    cat > "docker-images.json" << EOF
{
  "version": "${VERSION}",
  "registry": "${REGISTRY}",
  "images": {
    "base": {
      "name": "${REGISTRY}/crowdsec-manager:${VERSION}",
      "latest": "${REGISTRY}/crowdsec-manager:latest",
      "description": "Base CrowdSec Manager image with multi-proxy support",
      "platforms": ["linux/amd64", "linux/arm64"],
      "size_mb": "~150"
    },
    "proxy_specific": {
      "traefik": {
        "name": "${REGISTRY}/crowdsec-manager:${VERSION}-traefik",
        "latest": "${REGISTRY}/crowdsec-manager:latest-traefik",
        "description": "CrowdSec Manager configured for Traefik",
        "features": ["whitelist", "captcha", "logs", "bouncer", "health", "addons"]
      },
      "nginx": {
        "name": "${REGISTRY}/crowdsec-manager:${VERSION}-nginx",
        "latest": "${REGISTRY}/crowdsec-manager:latest-nginx",
        "description": "CrowdSec Manager configured for Nginx Proxy Manager",
        "features": ["logs", "bouncer", "health"]
      },
      "caddy": {
        "name": "${REGISTRY}/crowdsec-manager:${VERSION}-caddy",
        "latest": "${REGISTRY}/crowdsec-manager:latest-caddy",
        "description": "CrowdSec Manager configured for Caddy",
        "features": ["bouncer", "health"]
      },
      "haproxy": {
        "name": "${REGISTRY}/crowdsec-manager:${VERSION}-haproxy",
        "latest": "${REGISTRY}/crowdsec-manager:latest-haproxy",
        "description": "CrowdSec Manager configured for HAProxy",
        "features": ["bouncer", "health"]
      },
      "zoraxy": {
        "name": "${REGISTRY}/crowdsec-manager:${VERSION}-zoraxy",
        "latest": "${REGISTRY}/crowdsec-manager:latest-zoraxy",
        "description": "CrowdSec Manager configured for Zoraxy (experimental)",
        "features": ["health"],
        "experimental": true
      },
      "standalone": {
        "name": "${REGISTRY}/crowdsec-manager:${VERSION}-standalone",
        "latest": "${REGISTRY}/crowdsec-manager:latest-standalone",
        "description": "CrowdSec Manager in standalone mode (no proxy)",
        "features": ["health"]
      }
    },
    "development": {
      "name": "${REGISTRY}/crowdsec-manager:${VERSION}-dev",
      "latest": "${REGISTRY}/crowdsec-manager:dev",
      "description": "Development image with hot reload",
      "features": ["hot_reload", "development_tools"]
    }
  },
  "usage": {
    "basic": "docker run -d -p 8080:8080 ${REGISTRY}/crowdsec-manager:${VERSION}",
    "traefik": "docker-compose --profile traefik up -d",
    "nginx": "docker-compose --profile nginx up -d",
    "development": "docker run -d -v \$(pwd):/app ${REGISTRY}/crowdsec-manager:dev"
  }
}
EOF
    
    log_success "Image manifest generated: docker-images.json"
}

# Main execution
main() {
    log_info "Starting CrowdSec Manager Docker image build process..."
    log_info "Registry: ${REGISTRY}"
    log_info "Version: ${VERSION}"
    log_info "Platforms: ${PLATFORMS}"
    log_info "Push to registry: ${PUSH}"
    
    check_prerequisites
    
    # Build images
    build_base_image
    build_proxy_images
    build_dev_image
    
    # Generate manifest
    generate_manifest
    
    log_success "All Docker images built successfully!"
    log_info "Image manifest: docker-images.json"
    
    if [ "${PUSH}" = "true" ]; then
        log_success "Images pushed to registry: ${REGISTRY}"
    else
        log_info "Images built locally. Use PUSH=true to push to registry."
    fi
}

# Help function
show_help() {
    cat << EOF
CrowdSec Manager Docker Image Build Script

Usage: $0 [OPTIONS]

Options:
  -r, --registry REGISTRY    Docker registry (default: crowdsec-manager)
  -v, --version VERSION      Image version (default: 2.0.0)
  -p, --platforms PLATFORMS  Target platforms (default: linux/amd64,linux/arm64)
  --push                     Push images to registry (default: false)
  --dev-only                 Build only development image
  --base-only                Build only base image
  -h, --help                 Show this help message

Examples:
  $0                                          # Build all images locally
  $0 --push                                   # Build and push all images
  $0 -r myregistry/crowdsec -v 2.1.0 --push # Custom registry and version
  $0 --dev-only                              # Build only development image

Environment Variables:
  REGISTRY    Docker registry prefix
  VERSION     Image version tag
  PLATFORMS   Target platforms for multi-arch build
  PUSH        Push to registry (true/false)
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--registry)
            REGISTRY="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -p|--platforms)
            PLATFORMS="$2"
            shift 2
            ;;
        --push)
            PUSH="true"
            shift
            ;;
        --dev-only)
            DEV_ONLY="true"
            shift
            ;;
        --base-only)
            BASE_ONLY="true"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Execute based on options
if [ "${DEV_ONLY}" = "true" ]; then
    check_prerequisites
    build_dev_image
elif [ "${BASE_ONLY}" = "true" ]; then
    check_prerequisites
    build_base_image
else
    main
fi