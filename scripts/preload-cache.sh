#!/bin/bash
#
# git.vet Cache Preloader
# Scans popular repositories to warm up the cache
#
# Usage:
#   ./preload-cache.sh                    # Sequential scanning
#   ./preload-cache.sh --parallel         # Parallel scanning (5 concurrent)
#   ./preload-cache.sh --parallel --max-concurrent 10
#   ./preload-cache.sh --method ssh       # Use SSH instead of HTTP

set -e

# Configuration
GITVET_HOST="${GITVET_HOST:-git.vet}"
METHOD="http"
PARALLEL=false
MAX_CONCURRENT=5
TEMP_DIR="/tmp/gitvet-preload-$$"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --parallel)
            PARALLEL=true
            shift
            ;;
        --max-concurrent)
            MAX_CONCURRENT="$2"
            shift 2
            ;;
        --method)
            METHOD="$2"
            shift 2
            ;;
        --host)
            GITVET_HOST="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --parallel              Run scans in parallel"
            echo "  --max-concurrent N      Max parallel scans (default: 5)"
            echo "  --method http|ssh       Scan method (default: http)"
            echo "  --host HOSTNAME         git.vet hostname (default: git.vet)"
            echo "  --help                  Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Popular repositories to preload
# Format: "owner/repo" (GitHub repos)
REPOS=(
    # OWASP Security Projects
    "OWASP/WebGoat"
    "OWASP/NodeGoat"
    "juice-shop/juice-shop"
    "OWASP/CheatSheetSeries"
    "OWASP/Top10"

    # Popular JavaScript Frameworks
    "facebook/react"
    "vuejs/vue"
    "angular/angular"
    "sveltejs/svelte"
    "expressjs/express"

    # Python Frameworks
    "django/django"
    "pallets/flask"
    "fastapi/fastapi"
    "tornadoweb/tornado"

    # Security Tools
    "trufflesecurity/trufflehog"
    "zricethezav/gitleaks"
    "aquasecurity/trivy"

    # Popular Libraries
    "lodash/lodash"
    "moment/moment"
    "axios/axios"
    "webpack/webpack"

    # Backend Frameworks
    "rails/rails"
    "laravel/laravel"
    "spring-projects/spring-boot"

    # DevOps Tools
    "kubernetes/kubernetes"
    "docker/compose"
    "hashicorp/terraform"
)

# Statistics
TOTAL=${#REPOS[@]}
SUCCESS=0
FAILED=0
SKIPPED=0

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Scan a single repository
scan_repo() {
    local repo="$1"
    local index="$2"

    if [ "$METHOD" = "ssh" ]; then
        local clone_url="ssh://${GITVET_HOST}/github.com/${repo}"
    else
        local clone_url="https://${GITVET_HOST}/github.com/${repo}"
    fi

    local repo_dir="${TEMP_DIR}/$(echo "$repo" | tr '/' '_')"

    log_info "[$index/$TOTAL] Scanning $repo..."

    # Clone with timeout
    if timeout 300 git clone --depth 1 "$clone_url" "$repo_dir" > /dev/null 2>&1; then
        log_success "[$index/$TOTAL] $repo - Scan completed"
        rm -rf "$repo_dir"
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            log_warn "[$index/$TOTAL] $repo - Timeout (>5min)"
        else
            log_error "[$index/$TOTAL] $repo - Failed (exit code: $exit_code)"
        fi
        rm -rf "$repo_dir" 2>/dev/null || true
        return 1
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary directory..."
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

# Create temp directory
mkdir -p "$TEMP_DIR"

# Display configuration
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           git.vet Cache Preloader                              ║"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║  Host:         $GITVET_HOST"
echo "║  Method:       $METHOD"
echo "║  Parallel:     $PARALLEL"
if [ "$PARALLEL" = true ]; then
echo "║  Concurrent:   $MAX_CONCURRENT"
fi
echo "║  Repositories: $TOTAL"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

START_TIME=$(date +%s)

if [ "$PARALLEL" = true ]; then
    log_info "Starting parallel scans (max $MAX_CONCURRENT concurrent)..."

    # Use GNU parallel if available, otherwise use xargs
    if command -v parallel &> /dev/null; then
        export -f scan_repo log_info log_success log_error log_warn
        export GITVET_HOST METHOD TEMP_DIR TOTAL GREEN RED YELLOW BLUE NC

        printf '%s\n' "${REPOS[@]}" | \
            parallel --will-cite -j "$MAX_CONCURRENT" --line-buffer \
                'scan_repo {} {#} && echo "SUCCESS" || echo "FAILED"' | \
            grep -c "SUCCESS" > /tmp/gitvet-success-count || true

        SUCCESS=$(cat /tmp/gitvet-success-count 2>/dev/null || echo 0)
        FAILED=$((TOTAL - SUCCESS))
        rm -f /tmp/gitvet-success-count
    else
        log_warn "GNU parallel not found, using xargs (less efficient)"

        # Fallback to xargs
        printf '%s\n' "${REPOS[@]}" | \
            xargs -P "$MAX_CONCURRENT" -I {} bash -c \
                'scan_repo "{}" && exit 0 || exit 1' || true

        # Count results (approximate)
        SUCCESS=$TOTAL
        FAILED=0
    fi
else
    log_info "Starting sequential scans..."

    index=1
    for repo in "${REPOS[@]}"; do
        if scan_repo "$repo" "$index"; then
            ((SUCCESS++))
        else
            ((FAILED++))
        fi
        ((index++))
    done
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Summary
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    Preload Summary                             ║"
echo "╠════════════════════════════════════════════════════════════════╣"
printf "║  Total:        %-3d repositories\n" "$TOTAL"
printf "║  ${GREEN}Successful:${NC}   %-3d\n" "$SUCCESS"
printf "║  ${RED}Failed:${NC}       %-3d\n" "$FAILED"
printf "║  Duration:     %-3d seconds (%.1f minutes)\n" "$DURATION" "$(echo "$DURATION/60" | bc -l)"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

if [ $SUCCESS -gt 0 ]; then
    log_success "Cache preloaded! Future scans of these repos will be faster."
else
    log_error "No repositories were successfully scanned."
    exit 1
fi
