#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

KAM_URL="https://mcgrail.com/downloads/KAM.cf"
TIMESTAMP_FILE="$SCRIPT_DIR/.last-modified"
LOGFILE="$SCRIPT_DIR/update.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

# Get remote Last-Modified timestamp via HEAD request
log "Checking KAM.cf for updates..."
REMOTE_TIMESTAMP=$(curl -sI "$KAM_URL" | grep -i '^Last-Modified:' | cut -d' ' -f2- | tr -d '\r')

if [[ -z "$REMOTE_TIMESTAMP" ]]; then
    log "ERROR: Could not fetch Last-Modified header from $KAM_URL"
    exit 1
fi

log "Remote timestamp: $REMOTE_TIMESTAMP"

# Check if we have a stored timestamp
if [[ -f "$TIMESTAMP_FILE" ]]; then
    LOCAL_TIMESTAMP=$(cat "$TIMESTAMP_FILE")
    log "Local timestamp:  $LOCAL_TIMESTAMP"

    if [[ "$REMOTE_TIMESTAMP" == "$LOCAL_TIMESTAMP" ]]; then
        log "No changes detected. Skipping update."
        exit 0
    fi

    log "Changes detected!"
else
    log "No local timestamp found. First run."
fi

# Update detected - download and compile
log "Downloading and compiling KAM.cf..."
if python3 kam_rspamd.py >> "$LOGFILE" 2>&1; then
    log "Successfully compiled KAM.cf"

    # Store new timestamp
    echo "$REMOTE_TIMESTAMP" > "$TIMESTAMP_FILE"
    log "Updated local timestamp"

    # Optional: auto-deploy to rspamd
    # Uncomment the following lines to auto-deploy:
    # log "Deploying to rspamd..."
    # sudo cp dist/kam.lua /etc/rspamd/plugins.d/kam.lua
    # sudo rspamadm configtest && sudo systemctl restart rspamd
    # log "Deployed and restarted rspamd"

    log "Update complete. New rules available in dist/kam.lua"
else
    log "ERROR: Compilation failed"
    exit 1
fi
