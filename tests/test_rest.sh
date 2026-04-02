#!/usr/bin/env bash
 
HOST="${1:-127.0.0.1}"
PORT="8080"
BASE="http://${HOST}:${PORT}"
KEY="sdn-lab-secret-2025"      # must match FIREWALL_API_KEY in config.py
AUTH="-H \"X-API-Key: ${KEY}\""

PASS=0
FAIL=0

# ── helper ────────────────────────────────────────────────────────────────────
run() {
    local label="$1"; shift
    echo ""
    echo "━━━ ${label} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    HTTP=$(curl -s -o /tmp/ryu_resp -w "%{http_code}" \
           -H "X-API-Key: ${KEY}" \
           -H "Content-Type: application/json" \
           "$@")
    BODY=$(cat /tmp/ryu_resp)
    echo "HTTP ${HTTP}"
    echo "${BODY}" | python3 -m json.tool 2>/dev/null || echo "${BODY}"
    if [[ "${HTTP}" =~ ^2 ]]; then
        echo "✓ PASS"
        PASS=$((PASS+1))
    else
        echo "✗ FAIL"
        FAIL=$((FAIL+1))
    fi
}

# ── health (no auth needed) ───────────────────────────────────────────────────
run "GET /health (no auth)" \
    "${BASE}/health"

# ── topology ──────────────────────────────────────────────────────────────────
run "GET /topology" \
    "${BASE}/topology"

# ── switches ──────────────────────────────────────────────────────────────────
run "GET /switches" \
    "${BASE}/switches"

# ── MAC table ─────────────────────────────────────────────────────────────────
run "GET /mactable" \
    "${BASE}/mactable"

# ── list rules (should be empty at start) ────────────────────────────────────
run "GET /firewall/rules (empty)" \
    "${BASE}/firewall/rules"

# ── block a host ─────────────────────────────────────────────────────────────
echo ""
echo "━━━ POST /firewall/rules — block ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
BLOCK_RESP=$(curl -s \
    -X POST "${BASE}/firewall/rules" \
    -H "X-API-Key: ${KEY}" \
    -H "Content-Type: application/json" \
    -d '{"action":"block","src_ip":"10.0.0.5","idle_timeout":120,"source":"manual"}')
echo "${BLOCK_RESP}" | python3 -m json.tool
BLOCK_ID=$(echo "${BLOCK_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('rule_id',''))" 2>/dev/null)
if [ -n "${BLOCK_ID}" ]; then
    echo "✓ PASS — rule_id=${BLOCK_ID}"
    PASS=$((PASS+1))
else
    echo "✗ FAIL — no rule_id in response"
    FAIL=$((FAIL+1))
fi

# ── rate limit ───────────────────────────────────────────────────────────────
echo ""
echo "━━━ POST /firewall/rules — ratelimit ━━━━━━━━━━━━━━━━━━━━━━━━━━"
RATE_RESP=$(curl -s \
    -X POST "${BASE}/firewall/rules" \
    -H "X-API-Key: ${KEY}" \
    -H "Content-Type: application/json" \
    -d '{"action":"ratelimit","src_ip":"10.0.0.6","rate_kbps":500,"source":"manual"}')
echo "${RATE_RESP}" | python3 -m json.tool
RATE_ID=$(echo "${RATE_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('rule_id',''))" 2>/dev/null)
if [ -n "${RATE_ID}" ]; then
    echo "✓ PASS — rule_id=${RATE_ID}"
    PASS=$((PASS+1))
else
    echo "✗ FAIL — no rule_id in response (switch must be connected)"
    FAIL=$((FAIL+1))
fi

# ── isolate ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━ POST /firewall/rules — isolate ━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ISO_RESP=$(curl -s \
    -X POST "${BASE}/firewall/rules" \
    -H "X-API-Key: ${KEY}" \
    -H "Content-Type: application/json" \
    -d '{"action":"isolate","src_ip":"10.0.0.7","source":"manual"}')
echo "${ISO_RESP}" | python3 -m json.tool
ISO_ID=$(echo "${ISO_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('rule_id',''))" 2>/dev/null)
if [ -n "${ISO_ID}" ]; then
    echo "✓ PASS — rule_id=${ISO_ID}"
    PASS=$((PASS+1))
else
    echo "✗ FAIL — no rule_id"
    FAIL=$((FAIL+1))
fi

# ── list rules (should now have 3) ───────────────────────────────────────────
run "GET /firewall/rules (should have 3)" \
    "${BASE}/firewall/rules"

# ── get single rule ───────────────────────────────────────────────────────────
if [ -n "${BLOCK_ID}" ]; then
    run "GET /firewall/rules/${BLOCK_ID}" \
        "${BASE}/firewall/rules/${BLOCK_ID}"
fi

# ── delete the block rule ─────────────────────────────────────────────────────
if [ -n "${BLOCK_ID}" ]; then
    run "DELETE /firewall/rules/${BLOCK_ID}" \
        -X DELETE "${BASE}/firewall/rules/${BLOCK_ID}"
fi
 
run "GET /firewall/rules (after delete, should have 2)" \
    "${BASE}/firewall/rules?active=true"

# ── dump state to log ─────────────────────────────────────────────────────────
run "GET /dump" \
    "${BASE}/dump"

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "════════════════════════════════════════════"