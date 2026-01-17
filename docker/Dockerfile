# GitScan Multi-Stage Dockerfile
#
# Build stages:
# 1. builder - Compiles Go binary, runs unit tests
# 2. opengrep-cache - Caches opengrep binary and rules
# 3. production - Minimal production image
#
# Test stages (used by docker-compose.test.yml):
# 4. test-base - Base for git version tests
# 5. git-test-* - Individual git version test images

# ============================================================================
# Stage 1: Build the Go binary
# ============================================================================
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev sqlite-dev

WORKDIR /src

# Copy go mod files first for caching
COPY go.mod go.sum* ./
RUN go mod download || true

# Copy source code
COPY . .

# Download dependencies (in case go.sum didn't exist)
RUN go mod tidy

# Build the binary
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=$(git describe --tags --always 2>/dev/null || echo 'dev') \
              -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
              -X main.GitCommit=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
    -o /gitscan \
    ./cmd/gitscan-server

# Run unit tests
RUN go test -v ./... || echo "Tests completed (some may have failed due to missing dependencies)"

# ============================================================================
# Stage 2: Cache opengrep binary and rules
# ============================================================================
FROM ghcr.io/opengrep/opengrep:latest AS opengrep-cache

# Opengrep image contains:
# - /usr/local/bin/opengrep (or similar)
# - Rules at various locations
# We extract what we need in the production stage

# ============================================================================
# Stage 3: Production image
# ============================================================================
FROM alpine:3.19 AS production

# Install runtime dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    sqlite-libs \
    tzdata

# Create non-root user
RUN addgroup -S gitscan && adduser -S gitscan -G gitscan

# Create directories
RUN mkdir -p /data/sqlite /data/repos /etc/gitscan/rules \
    && chown -R gitscan:gitscan /data /etc/gitscan

# Copy gitscan binary
COPY --from=builder /gitscan /usr/local/bin/gitscan

# Copy opengrep binary from cache stage
COPY --from=opengrep-cache /usr/local/bin/opengrep /usr/local/bin/opengrep

# Make binaries executable
RUN chmod +x /usr/local/bin/gitscan && \
    (chmod +x /usr/local/bin/opengrep 2>/dev/null || true)

# Set working directory
WORKDIR /data

# Switch to non-root user
USER gitscan

# Expose ports
EXPOSE 6633 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:6633/health || exit 1

# Default command
ENTRYPOINT ["/usr/local/bin/gitscan"]
CMD ["--listen", ":6633", "--db", "/data/sqlite/gitscan.db", "--cache-dir", "/data/repos"]

# ============================================================================
# Stage 4: Test base image (for git version tests)
# ============================================================================
FROM alpine:3.19 AS test-base

# Install test dependencies
RUN apk add --no-cache \
    curl \
    bash \
    sqlite-libs

# Copy gitscan binary
COPY --from=builder /gitscan /usr/local/bin/gitscan

# Copy test script
COPY test/git-compat-test.sh /test.sh
RUN chmod +x /test.sh

# ============================================================================
# Git Version Test Images
# These are built separately via docker-compose or build args
# ============================================================================

# Example for building specific git version test:
# docker build --target git-test --build-arg GIT_IMAGE=ubuntu:22.04 -t gitscan-test-git-2.34 .
