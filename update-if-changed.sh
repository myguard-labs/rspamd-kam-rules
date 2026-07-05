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
if ! curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 120 -o "$SOURCE_FILE" "$KAM_URL"; then
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
    # Deploy the rule map — the thin plugin (dist/kam.lua) is static and only
    # changes on a runtime-code change (regenerate it with --emit-lua), so an
    # upstream KAM.cf change ships the map alone.
    # log "Deploying to rspamd..."
    # sudo install -m 0644 dist/kam_rules.map /etc/rspamd/kam_rules.map
    # Merge examples/kam.conf into /etc/rspamd/rspamd.conf.local once.
    # The plugin registers native regexps (combined Hyperscan DB) at config load,
    # so a full reconfigure is required to pick up an updated map:
    #   `systemctl reload rspamd` (SIGHUP) re-runs plugin init.
    #   `rspamadm control reload` does NOT — it reloads maps/stats only, not Lua
    #   plugin registration, so it would silently keep the old rules.
    # sudo rspamadm configtest && sudo systemctl reload rspamd
    # log "Deployed and reloaded rspamd"

    log "Update complete. New rules in dist/kam_rules.map (kam.lua unchanged)"
else
    log "ERROR: Compilation failed"
    exit 1
fi
