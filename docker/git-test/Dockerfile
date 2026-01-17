# Git Version Test Dockerfile
#
# This Dockerfile is used to test gitscan against different git versions.
# It copies the pre-built gitscan binary and runs compatibility tests.
#
# Usage:
#   docker build --build-arg GIT_BASE=ubuntu:22.04 -t gitscan-test-git-2.34 -f docker/git-test/Dockerfile .

ARG GIT_BASE=ubuntu:22.04

# ============================================================================
# Builder stage (reused from main Dockerfile)
# ============================================================================
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git gcc musl-dev sqlite-dev

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .
RUN go mod tidy
RUN CGO_ENABLED=1 GOOS=linux go build -o /gitscan ./cmd/gitscan-server

# ============================================================================
# Test stage with specific git version
# ============================================================================
FROM ${GIT_BASE} AS tester

# Install git based on distro
RUN if command -v apt-get >/dev/null 2>&1; then \
        apt-get update && apt-get install -y git curl netcat-openbsd sqlite3 && rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
        apk add --no-cache git curl netcat-openbsd sqlite; \
    elif command -v yum >/dev/null 2>&1; then \
        yum install -y git curl nc sqlite && yum clean all; \
    fi

# Copy gitscan binary from builder
COPY --from=builder /gitscan /usr/local/bin/gitscan
RUN chmod +x /usr/local/bin/gitscan

# Copy test script
COPY test/git-compat-test.sh /test.sh
RUN chmod +x /test.sh

# Create test directories
RUN mkdir -p /data/sqlite /data/repos /tmp/test-output

# Display git version for logging
RUN echo "Git version:" && git --version

# Set environment variables for tests
ENV GITSCAN_DB_PATH=/data/sqlite/test.db
ENV GITSCAN_CACHE_DIR=/data/repos
ENV GITSCAN_TEST_OUTPUT=/tmp/test-output

# Run tests at build time
# This ensures the build fails if tests fail
RUN /test.sh

# If we get here, tests passed
RUN echo "All tests passed for git $(git --version)"
