#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

KAM_URL="https://mcgrail.com/downloads/KAM.cf"
SOURCE_FILE=$(mktemp "$SCRIPT_DIR/.KAM.cf.XXXXXX")
trap 'rm -f "$SOURCE_FILE"' EXIT

# Emit to stdout/stderr only; the cron entry owns the redirect to update.log.
# (Self-logging via `tee -a` here AND a cron `>>update.log` doubled every line.)
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "Checking KAM.cf for updates..."
if ! curl -fsSL --retry 3 --retry-delay 2 -o "$SOURCE_FILE" "$KAM_URL"; then
    log "ERROR: Could not download $KAM_URL"
    exit 1
fi

SOURCE_SHA=$(sha256sum "$SOURCE_FILE" | awk '{print $1}')
CURRENT_SHA=$(
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("source_sha256", ""))' \
        "$SCRIPT_DIR/dist/report.json" 2>/dev/null || true
)
log "Downloaded source SHA-256: $SOURCE_SHA"

if [[ "$SOURCE_SHA" == "$CURRENT_SHA" ]]; then
    log "No content changes detected. Skipping update."
    exit 0
fi

log "Content changed; compiling KAM.cf..."
if python3 kam_rspamd.py \
    --input "$SOURCE_FILE" \
    --url "$KAM_URL" \
    --expected-sha256 "$SOURCE_SHA"; then
    log "Successfully compiled KAM.cf"

    # Optional: auto-deploy to rspamd
    # Uncomment the following lines to auto-deploy:
    # log "Deploying to rspamd..."
    # sudo install -m 0644 dist/kam.lua /etc/rspamd/plugins.d/kam.lua
    # Merge config/kam.conf into /etc/rspamd/rspamd.conf.local once.
    # sudo rspamadm configtest && sudo systemctl restart rspamd
    # log "Deployed and restarted rspamd"

    log "Update complete. New rules available in dist/kam.lua"
else
    log "ERROR: Compilation failed"
    exit 1
fi
