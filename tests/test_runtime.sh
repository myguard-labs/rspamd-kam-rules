#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RSPAMD_IMAGE="${RSPAMD_IMAGE:-rspamd/rspamd:4.1.0}"
TMPDIR=$(mktemp -d)
CONTAINER=""
PORT=""

cleanup() {
    if [[ -n "$CONTAINER" ]]; then
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

start_rspamd() {
    local plugin=$1
    local map=$2
    local config=$3
    local local_lua=${4:-}
    local args=(
        run -d --rm
        --name "rspamd-kam-runtime-$$-$RANDOM"
        -p 127.0.0.1::11333
        -v "$plugin:/etc/rspamd/plugins.d/kam.lua:ro"
        -v "$map:/etc/rspamd/kam_rules.map:ro"
        -v "$config:/etc/rspamd/rspamd.conf.local:ro"
    )

    if [[ -n "$CONTAINER" ]]; then
        docker rm -f "$CONTAINER" >/dev/null
    fi
    if [[ -n "$local_lua" ]]; then
        args+=(-v "$local_lua:/etc/rspamd/rspamd.local.lua:ro")
    fi
    args+=("$RSPAMD_IMAGE")
    CONTAINER=$(docker "${args[@]}")
    PORT=$(docker port "$CONTAINER" 11333/tcp | sed 's/.*://')

    for _ in $(seq 1 60); do
        if curl -fsS "http://127.0.0.1:$PORT/ping" >/dev/null 2>&1; then
            return
        fi
        sleep 0.25
    done
    docker logs "$CONTAINER"
    return 1
}

scan() {
    curl -fsS \
        -H "Content-Type: message/rfc822" \
        --data-binary "$1" \
        "http://127.0.0.1:$PORT/checkv2"
}

assert_symbol_score() {
    local symbol=$1
    local expected=$2
    python3 -c '
import json
import math
import sys

symbol, expected = sys.argv[1], float(sys.argv[2])
result = json.load(sys.stdin)
actual = result.get("symbols", {}).get(symbol)
if actual is None:
    raise SystemExit(f"{symbol} was not inserted: {result}")
if not math.isclose(float(actual["score"]), expected, rel_tol=0, abs_tol=1e-9):
    raise SystemExit(f"{symbol} score {actual['score']} != {expected}")
' "$symbol" "$expected"
}

assert_log() {
    local pattern=$1
    local logs
    logs=$(docker logs "$CONTAINER" 2>&1)
    if ! grep -Eq "$pattern" <<<"$logs"; then
        printf 'Container log did not match %s:\n%s\n' "$pattern" "$logs" >&2
        return 1
    fi
}

assert_no_log() {
    local pattern=$1
    local logs
    logs=$(docker logs "$CONTAINER" 2>&1)
    if grep -Eq "$pattern" <<<"$logs"; then
        printf 'Container log matched forbidden pattern %s:\n%s\n' \
            "$pattern" "$(grep -E "$pattern" <<<"$logs")" >&2
        return 1
    fi
}

cd "$ROOT"
install -m 0644 dist/kam.lua "$TMPDIR/kam.lua"
install -m 0644 dist/kam_rules.map "$TMPDIR/kam_rules.map"
# Pin the map to the mounted file; the bundled-map init path (native register +
# combined-DB compile at config load) is what we exercise here.
cat > "$TMPDIR/rspamd.conf.local" <<'EOF'
kam {
    enabled = true;
    map_path = "/etc/rspamd/kam_rules.map";
    # Disable the self-update poll for the correctness run: keep it offline and
    # deterministic (no github fetch), and force the seed path (no /var/lib cache
    # to shadow it). The download-only watch is exercised separately below.
    map_url = "";
}
EOF
chmod 0644 "$TMPDIR/rspamd.conf.local"
start_rspamd "$TMPDIR/kam.lua" "$TMPDIR/kam_rules.map" "$TMPDIR/rspamd.conf.local"

assert_log "loaded [0-9]+ generated KAM Lua rules"

# Regression guard: the external-dependency wiring in kam.lua must never register
# KAM_RULES_MODULE against an absent symbol (e.g. OLETOOLS_ENCRYPTED with olefy
# disabled) or a pure composite (e.g. FREEMAIL_REPLYTO_NEQ_FROM). Either makes
# rspamd log a symcache dependency error at config load. The shipped map carries
# both kinds in external_dependencies, so this exercises the guard for real.
assert_no_log "cannot register delayed dependency KAM_RULES_MODULE|invalid symbol types"

scan $'From: a@example.com\nTo: b@example.com\nSubject: The TRUTH\n\nordinary text' |
    assert_symbol_score KAM_TRUTHINESS 1.5

scan $'From: a@example.com\nTo: b@example.com\nSubject: ordinary\n\nhttps://storage.googleapis.com/bucket-one/path/file.html https://storage.googleapis.com/bucket-two/path/file.html' |
    assert_symbol_score GB_STORAGE_GOOGLE_HTM 2.5

# Slow path: a header rule with an addr transform (From:addr =~ /adv@/i) does NOT
# ride the combined Hyperscan DB — it parses each address in Lua. Exercise it so
# the addr/name fallback can't silently regress.
scan $'From: adv@evilcorp.com\nTo: b@example.com\nSubject: ordinary\n\nbody' |
    assert_symbol_score KAM_ADV_EMAIL 5.0

# ---------------------------------------------------------------------------
# Bulk real-rule smoke test. A single crafted spam sample (tests/fixtures/
# kam-multi-hit.eml) is designed to trip a broad spread of the SHIPPED KAM
# rules — body + rawbody, mixed scores — against the live combined Hyperscan
# DB. Guards against a converter/parser regression silently gutting the real
# ruleset (unit tests use synthetic rules; this exercises kam.cf's own regexes
# end to end). If a rule below disappears upstream, drop it from the list; the
# point is that MANY shipped rules fire, not these exact ones.
kam_bulk_result=$(scan "$(cat "$ROOT/tests/fixtures/kam-multi-hit.eml")")
for pair in \
    KAM_LEAD_SUPPLY:10.0 \
    KAM_PUBLIC:9.0 \
    KAM_ADVERT3:5.0 \
    KAM_CBTSCRAP:5.0 \
    KAM_REACHBASE:2.5 \
    KAM_TRUTHINESS:1.5 \
    KAM_NOT_INTERESTED:1.5 \
    KAM_CANSPAM:1.0 \
    KAM_HTTP_REFRESH:1.0 \
    KAM_ADVERT4:0.75 \
    KAM_ADVERT2:0.75; do
    printf '%s' "$kam_bulk_result" | assert_symbol_score "${pair%%:*}" "${pair##*:}"
done
echo "bulk real-KAM-rule sample fired 11 shipped rules"

python3 - "$TMPDIR/dependency.lua" "$TMPDIR/dependency.map" <<'PY'
import sys
from pathlib import Path

import kam_rspamd

source = (
    b"body LOCAL /dependency-trigger/\n"
    b"body BAD /(/\n"
    b"score BAD 1\n"
    b"meta DEP_META (LOCAL && AUDIT_EXTERNAL)\n"
    b"score DEP_META 2\n"
)
converted, mapdata, _ = kam_rspamd.convert(
    source,
    "fixture://runtime",
    min_bytes=1,
    min_rules=1,
    external_symbols={"AUDIT_EXTERNAL"},
)
kam_rspamd.atomic_write(Path(sys.argv[1]), converted)
kam_rspamd.atomic_write(Path(sys.argv[2]), mapdata)
PY

cat > "$TMPDIR/rspamd.local.lua" <<'LUA'
rspamd_config:register_symbol({
  name = 'AUDIT_EXTERNAL',
  type = 'normal',
  priority = -10,
  score = 0.01,
  callback = function() return true end,
})
LUA
chmod 0644 "$TMPDIR/rspamd.local.lua"

start_rspamd \
    "$TMPDIR/dependency.lua" \
    "$TMPDIR/dependency.map" \
    "$TMPDIR/rspamd.conf.local" \
    "$TMPDIR/rspamd.local.lua"

scan $'From: a@example.com\nTo: b@example.com\nSubject: ordinary\n\ndependency-trigger' |
    assert_symbol_score DEP_META 2
assert_log "cannot compile KAM regexp BAD"

# ---------------------------------------------------------------------------
# Native + slow-path branch matrix. One synthetic ruleset covers every scan
# branch the Hyperscan rearchitecture introduced; a single crafted message
# fires them all so each branch is proven against live rspamd 4.1.0, not just
# the generator. Branches: negate, multiple+maxhits, rawheader, ALL pseudo-
# header, ToCc/MESSAGEID multi-header aliases, rawbody, full, header name-mode.
# ---------------------------------------------------------------------------
python3 - "$TMPDIR/matrix.lua" "$TMPDIR/matrix.map" <<'PY'
import sys
from pathlib import Path

import kam_rspamd

source = (
    # negate: fires when From does NOT match (it won't here)
    b"header NEG_RULE From !~ /nope@absent/i\n"
    b"score NEG_RULE 1\n"
    # multiple + maxhits: body has 5 'multimark', capped at 3 hits
    b"body MULTI_RULE /multimark/\n"
    b"tflags MULTI_RULE multiple maxhits=3\n"
    b"score MULTI_RULE 1\n"
    # rawheader native path
    b"header RAWH_RULE X-Test:raw =~ /RAWVAL/\n"
    b"score RAWH_RULE 1\n"
    # ALL pseudo-header slow path (get_raw_headers blob)
    b"header ALL_RULE ALL =~ /X-Marker: yes/i\n"
    b"score ALL_RULE 1\n"
    # ALL pseudo-header + multiple/maxhits (matchn count path)
    b"header ALLM_RULE ALL =~ /X-Dup:/\n"
    b"tflags ALLM_RULE multiple maxhits=2\n"
    b"score ALLM_RULE 1\n"
    # ToCc multi-header alias slow path
    b"header TOCC_RULE ToCc =~ /target@example/i\n"
    b"score TOCC_RULE 1\n"
    # MESSAGEID multi-header alias slow path
    b"header MID_RULE MESSAGEID =~ /uniqmid/i\n"
    b"score MID_RULE 1\n"
    # rawbody native scan type
    b"rawbody RB_RULE /rawbodymark/\n"
    b"score RB_RULE 1\n"
    # full (rawmime) native scan type
    b"full FULL_RULE /fullmsgmark/\n"
    b"score FULL_RULE 1\n"
    # header name-mode slow path (display-name transform)
    b"header NAME_RULE From:name =~ /Sketchy/\n"
    b"score NAME_RULE 1\n"
    # negate + multiple on the SLOW path (addr transform). From:addr is present
    # but does NOT match, so hits==0 and negate must invert to a single hit.
    # Guards the Lua-truthiness bug where (multiple and hits or 1) returned 0
    # for hits==0 because 0 is truthy. Must score 1, never 0.
    b"header NEGADDR_RULE From:addr !~ /nomatch@nowhere/i\n"
    b"tflags NEGADDR_RULE multiple\n"
    b"score NEGADDR_RULE 1\n"
    # EnvelopeFrom pseudo-header slow path (SMTP MAIL FROM, resolved in Lua).
    b"header ENVFROM_RULE EnvelopeFrom =~ /envsender@example/i\n"
    b"score ENVFROM_RULE 1\n"
    # [if-unset:] fires when the header is ABSENT — the matrix message carries
    # no References header, so this must hit against the fallback value.
    b"header MISSING_REF_RULE References =~ /^UNSET$/ [if-unset: UNSET]\n"
    b"score MISSING_REF_RULE 1\n"
    # builtin evals (no external symbol, computed in eval_atom): body-length
    # trio on the short plain matrix message; HTML pair on the html message.
    b"meta BILT_SHORT (__KAM_BODY_LENGTH_LT_128 && __KAM_BODY_LENGTH_LT_512 && __KAM_BODY_LENGTH_LT_1024)\n"
    b"score BILT_SHORT 1\n"
    b"meta BILT_HTML (HTML_MESSAGE && __TAG_EXISTS_HEAD)\n"
    b"score BILT_HTML 1\n"
    # B3: multipart/alternative body-length dedup. A single alternative part
    # is ~300 bytes (< 512); double-counting both text/plain + text/html
    # siblings would cross 512 and make this meta fail to fire.
    b"meta BILT_ALT_LT512 (__KAM_BODY_LENGTH_LT_512)\n"
    b"score BILT_ALT_LT512 1\n"
    # B3 regression guard: unrelated plain + html parts under multipart/mixed
    # must both count. The earlier message-wide HTML shortcut skipped all plain
    # text and would incorrectly keep this below 512 bytes.
    b"meta BILT_MIXED_GE512 (!__KAM_BODY_LENGTH_LT_512)\n"
    b"score BILT_MIXED_GE512 1\n"
)
converted, mapdata, _ = kam_rspamd.convert(
    source, "fixture://matrix", min_bytes=1, min_rules=1,
)
kam_rspamd.atomic_write(Path(sys.argv[1]), converted)
kam_rspamd.atomic_write(Path(sys.argv[2]), mapdata)
PY

start_rspamd "$TMPDIR/matrix.lua" "$TMPDIR/matrix.map" "$TMPDIR/rspamd.conf.local"

# One message fires every branch. From has a display-name (name-mode) and an
# address that does NOT match NEG_RULE's regex (so negate inverts to a hit).
matrix_msg=$'From: "Sketchy Dude" <real@example.com>\nTo: target@example.com\nCc: other@example.com\nMessage-ID: <uniqmid@example.com>\nX-Test: RAWVAL\nX-Marker: yes\nX-Dup: a\nX-Dup: b\nX-Dup: c\nSubject: ordinary\n\nmultimark multimark multimark multimark multimark rawbodymark fullmsgmark'
matrix_result=$(scan "$matrix_msg")

printf '%s' "$matrix_result" | assert_symbol_score NEG_RULE 1     # negate inverted to hit
printf '%s' "$matrix_result" | assert_symbol_score MULTI_RULE 3   # 5 hits capped at maxhits=3
printf '%s' "$matrix_result" | assert_symbol_score RAWH_RULE 1    # rawheader native
printf '%s' "$matrix_result" | assert_symbol_score ALL_RULE 1     # ALL pseudo-header slow
printf '%s' "$matrix_result" | assert_symbol_score ALLM_RULE 2    # ALL + multiple, 3 hits capped at maxhits=2
printf '%s' "$matrix_result" | assert_symbol_score TOCC_RULE 1    # ToCc alias slow
printf '%s' "$matrix_result" | assert_symbol_score MID_RULE 1     # MESSAGEID alias slow
printf '%s' "$matrix_result" | assert_symbol_score RB_RULE 1      # rawbody native
printf '%s' "$matrix_result" | assert_symbol_score FULL_RULE 1    # full/rawmime native
printf '%s' "$matrix_result" | assert_symbol_score NAME_RULE 1    # header name-mode slow
printf '%s' "$matrix_result" | assert_symbol_score NEGADDR_RULE 1 # slow-path negate+multiple, hits==0 inverts to 1
printf '%s' "$matrix_result" | assert_symbol_score MISSING_REF_RULE 1  # if-unset fires on absent References header
printf '%s' "$matrix_result" | assert_symbol_score BILT_SHORT 1   # builtin body-length evals (75-char body)

# EnvelopeFrom resolves from the SMTP envelope (or Return-Path fallback). The
# matrix message has no envelope sender, so give this one a Return-Path that the
# runtime parses as the envelope From.
envfrom_msg=$'Return-Path: <envsender@example.com>\nFrom: a@example.com\nTo: b@example.com\nSubject: env test\n\nbody'
scan "$envfrom_msg" | assert_symbol_score ENVFROM_RULE 1          # EnvelopeFrom slow path via Return-Path

# HTML builtin evals need an actual text/html part with a <head> tag.
html_msg=$'From: a@example.com\nTo: b@example.com\nSubject: html test\nContent-Type: text/html\n\n<html><head><title>x</title></head><body>hello there</body></html>'
scan "$html_msg" | assert_symbol_score BILT_HTML 1                # builtin HTML_MESSAGE + __TAG_EXISTS_HEAD
echo "builtin eval symbols verified"

# multipart/alternative twin (text/plain + text/html, same rendered content):
# sa_body_length must count only the html part once, not both alternatives.
# Each alternative is a 300-byte filler: 300 < 512 (correct, single-counted)
# but 600 >= 512 (wrong, double-counted) — the LT_512 meta distinguishes them.
alt_fill=$(printf 'x%.0s' $(seq 1 300))
alt_msg=$(printf 'From: a@example.com\nTo: b@example.com\nSubject: alt test\nContent-Type: multipart/alternative; boundary="altbound"\n\n--altbound\nContent-Type: text/plain\n\n%s\n--altbound\nContent-Type: text/html\n\n<html><body>%s</body></html>\n--altbound--\n' "$alt_fill" "$alt_fill")
scan "$alt_msg" | assert_symbol_score BILT_ALT_LT512 1            # dedup: html-sibling plain part must not double-count body length
echo "multipart/alternative body-length dedup verified"

# Unrelated text/plain + text/html parts in multipart/mixed are not alternatives.
# Both 300-byte text parts count: 600 >= 512. A global "any HTML means skip all
# plain text" shortcut would wrongly count only the html part and miss this.
mixed_msg=$(printf 'From: a@example.com\nTo: b@example.com\nSubject: mixed test\nContent-Type: multipart/mixed; boundary="mixbound"\n\n--mixbound\nContent-Type: text/plain\n\n%s\n--mixbound\nContent-Type: text/html\n\n<html><body>%s</body></html>\n--mixbound--\n' "$alt_fill" "$alt_fill")
scan "$mixed_msg" | assert_symbol_score BILT_MIXED_GE512 1        # unrelated text parts must both contribute to body length
echo "multipart/mixed body-length counting verified"

# --- C1 self-update: download-only watch writes the cache copy ---------------
# Point map_url at a file:// source holding a DIFFERENT map and confirm rspamd's
# own add_map poll writes it to the cache path (atomic tmp+rename) at config
# load — WITHOUT it taking effect live (registration is config-load-only, so the
# fresh rule must NOT score until a reload). Proves: download works, write target
# is the rspamd-writable cache, and the watch never re-registers post-load.
upd_src="$TMPDIR/update_src.map"
cat > "$TMPDIR/update.cf" <<'CF'
body UPDATED_RULE /freshrulemark/
score UPDATED_RULE 4.0
CF
python3 - "$TMPDIR/update.lua" "$TMPDIR/seed.map" "$upd_src" <<'PY'
import sys
from pathlib import Path
import kam_rspamd
# seed.map: the shipped baseline (no UPDATED_RULE).
seed_lua, seed_map, _ = kam_rspamd.convert(
    b"body BASE /baserulemark/\nscore BASE 1\n", "fixture://seed", 1, 1)
kam_rspamd.atomic_write(Path(sys.argv[1]), seed_lua)
kam_rspamd.atomic_write(Path(sys.argv[2]), seed_map)
# update_src.map: a newer map the watch should download (adds UPDATED_RULE).
_, upd_map, _ = kam_rspamd.convert(
    b"body BASE /baserulemark/\nscore BASE 1\n"
    b"body UPDATED_RULE /freshrulemark/\nscore UPDATED_RULE 4\n",
    "fixture://update", 1, 1)
kam_rspamd.atomic_write(Path(sys.argv[3]), upd_map)
PY

cat > "$TMPDIR/update.conf.local" <<'EOF'
kam {
    enabled = true;
    map_path = "/etc/rspamd/kam_rules.map";
    cache_path = "/var/lib/rspamd/kam_rules.map";
    map_url = "file:///etc/rspamd/update_src.map";
    min_update_rules = 1;   # tiny synthetic map; the 500 default would reject it
}
EOF
chmod 0644 "$TMPDIR/update.conf.local"

upd_container="rspamd-kam-update-$$-$RANDOM"
docker run -d --rm --name "$upd_container" \
    -p 127.0.0.1::11333 \
    -v "$TMPDIR/update.lua:/etc/rspamd/plugins.d/kam.lua:ro" \
    -v "$TMPDIR/seed.map:/etc/rspamd/kam_rules.map:ro" \
    -v "$upd_src:/etc/rspamd/update_src.map:ro" \
    -v "$TMPDIR/update.conf.local:/etc/rspamd/rspamd.conf.local:ro" \
    "$RSPAMD_IMAGE" >/dev/null
upd_cleanup() { docker rm -f "$upd_container" >/dev/null 2>&1 || true; }
trap 'cleanup; upd_cleanup' EXIT
upd_port=$(docker port "$upd_container" 11333/tcp | sed 's/.*://')
for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:$upd_port/ping" >/dev/null 2>&1 && break
    sleep 0.25
done
# The watch fires on config load; give the async fetch a moment to land.
for _ in $(seq 1 40); do
    docker exec "$upd_container" test -f /var/lib/rspamd/kam_rules.map && break
    sleep 0.25
done
if ! docker exec "$upd_container" grep -q UPDATED_RULE /var/lib/rspamd/kam_rules.map; then
    echo "FAIL: self-update watch did not write the fresh map to the cache path" >&2
    docker logs "$upd_container" >&2
    exit 1
fi
# Download-only: the new rule must NOT be live yet (no reload happened).
upd_scan=$(curl -fsS -H "Content-Type: message/rfc822" \
    --data-binary $'Subject: t\n\nfreshrulemark baserulemark' \
    "http://127.0.0.1:$upd_port/checkv2")
if printf '%s' "$upd_scan" | grep -q '"UPDATED_RULE"'; then
    echo "FAIL: downloaded rule fired without a reload (watch must be download-only)" >&2
    exit 1
fi
printf '%s' "$upd_scan" | grep -q '"BASE"' || { echo "FAIL: seed rule BASE did not fire" >&2; exit 1; }
upd_cleanup
echo "C1 self-update download-only watch verified"

echo "Rspamd runtime tests passed"
