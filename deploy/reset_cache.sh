#!/bin/bash
set -e

# git.vet Cache Reset Script
# Clears file cache and database entries to force fresh scans
# Run as root: sudo ./deploy/reset_cache.sh

# Configuration
DATA_DIR="${GITVET_DATA_DIR:-/var/lib/gitvet}"
CACHE_DIR="$DATA_DIR/cache"
DB_PATH="$DATA_DIR/data/gitvet.db"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
FULL_RESET=false
QUIET=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --full)
            FULL_RESET=true
            shift
            ;;
        --quiet|-q)
            QUIET=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --full    Delete entire database (loses all scan history)"
            echo "  --quiet   Suppress non-error output"
            echo "  --help    Show this help message"
            echo ""
            echo "By default, clears file cache and removes malformed database entries"
            echo "while preserving valid scan history."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

log() {
    if [ "$QUIET" = false ]; then
        echo -e "$1"
    fi
}

log_warn() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

log_error() {
    echo -e "${RED}ERROR:${NC} $1" >&2
}

log_success() {
    if [ "$QUIET" = false ]; then
        echo -e "${GREEN}✓${NC} $1"
    fi
}

# Check for root (needed for /var/lib/gitvet)
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root: sudo $0"
    exit 1
fi

log "=== git.vet Cache Reset ==="
log ""

# Step 1: Clear file cache
if [ -d "$CACHE_DIR" ]; then
    FILE_COUNT=$(find "$CACHE_DIR" -type f 2>/dev/null | wc -l)
    DIR_COUNT=$(find "$CACHE_DIR" -mindepth 1 -type d 2>/dev/null | wc -l)

    log "Clearing file cache: $CACHE_DIR"
    rm -rf "$CACHE_DIR"/*
    log_success "Removed $FILE_COUNT files and $DIR_COUNT directories"
else
    log "Cache directory does not exist: $CACHE_DIR"
    mkdir -p "$CACHE_DIR"
    log_success "Created cache directory"
fi

# Step 2: Handle database
if [ -f "$DB_PATH" ]; then
    if [ "$FULL_RESET" = true ]; then
        log ""
        log "Full reset requested - deleting database..."
        rm -f "$DB_PATH"
        rm -f "$DB_PATH-wal" "$DB_PATH-shm" 2>/dev/null || true
        log_success "Database deleted (will be recreated on next start)"
    else
        log ""
        log "Cleaning malformed database entries..."

        # Check if sqlite3 is available
        if ! command -v sqlite3 &> /dev/null; then
            log_warn "sqlite3 not found - skipping database cleanup"
            log_warn "Install sqlite3 or use --full to delete the entire database"
        else
            # Count and remove malformed entries (duplicate host in URL)
            MALFORMED_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM repos WHERE url LIKE '%github.com/github.com%' OR url LIKE '%gitlab.com/gitlab.com%' OR url LIKE '%bitbucket.org/bitbucket.org%';" 2>/dev/null || echo "0")

            if [ "$MALFORMED_COUNT" -gt 0 ]; then
                log "Found $MALFORMED_COUNT malformed repo entries"

                # Get IDs of malformed repos for cascade delete
                MALFORMED_IDS=$(sqlite3 "$DB_PATH" "SELECT id FROM repos WHERE url LIKE '%github.com/github.com%' OR url LIKE '%gitlab.com/gitlab.com%' OR url LIKE '%bitbucket.org/bitbucket.org%';" 2>/dev/null | tr '\n' ',' | sed 's/,$//')

                if [ -n "$MALFORMED_IDS" ]; then
                    # Delete related scans first (foreign key)
                    sqlite3 "$DB_PATH" "DELETE FROM scans WHERE repo_id IN ($MALFORMED_IDS);" 2>/dev/null || true
                    # Delete the malformed repos
                    sqlite3 "$DB_PATH" "DELETE FROM repos WHERE id IN ($MALFORMED_IDS);" 2>/dev/null
                    log_success "Removed $MALFORMED_COUNT malformed entries and related scans"
                fi
            else
                log_success "No malformed entries found"
            fi

            # Clear repos where local path no longer exists
            ORPHAN_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM repos;" 2>/dev/null || echo "0")
            if [ "$ORPHAN_COUNT" -gt 0 ]; then
                # Update all repos to force re-fetch since we cleared the cache
                sqlite3 "$DB_PATH" "UPDATE repos SET last_fetched_at = NULL;" 2>/dev/null || true
                log_success "Reset fetch timestamps for $ORPHAN_COUNT repos (will re-fetch on next request)"
            fi

            # Vacuum to reclaim space
            sqlite3 "$DB_PATH" "VACUUM;" 2>/dev/null || true
        fi
    fi
else
    log "Database does not exist: $DB_PATH"
    log_success "Database will be created on next start"
fi

# Ensure correct ownership
if id "gitvet" &>/dev/null; then
    chown -R gitvet:gitvet "$DATA_DIR" 2>/dev/null || true
    log_success "Set ownership to gitvet:gitvet"
fi

log ""
log "=== Cache Reset Complete ==="
log ""
log "Restart the service to apply changes:"
log "  sudo systemctl restart gitvet"
