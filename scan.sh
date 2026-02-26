#!/usr/bin/env bash
# =============================================================================
# PQC KEM Scanner - Test domains for PQC/hybrid TLS key exchange support
# Uses: openquantumsafe/oqs-ossl3 Docker image
#
# Output: CSV with per-domain, per-group results
# Safety: throttled, TLS handshake only (no port scanning)
# =============================================================================

set -euo pipefail

# --- Configuration ---
DOMAINS_FILE="${1:-domains.txt}"
OUTPUT_DIR="pqc-results"
DELAY=2          # seconds between each test
TIMEOUT=10       # seconds per TLS attempt
PORT_DEFAULT=443

# Use a name that won't conflict with shell env
KEM_GROUPS=(
  # Start with the most common ML-KEM groups; add more after verifying via "list -groups"
  "X25519MLKEM768"
  "SecP256r1MLKEM768"
  "SecP384r1MLKEM1024"
  # "P256MLKEM768"

  # Optional / may vary by build (uncomment after verifying they exist)
  # "P256MLKEM768"
  "MLKEM768"
  "MLKEM512"
  "MLKEM1024"
)

DOCKER_IMAGE="openquantumsafe/oqs-ossl3"

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Helpers ---
die() { echo -e "${RED}Error: $*${NC}" >&2; exit 1; }

trim() {
  # trim leading/trailing whitespace
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf "%s" "$s"
}

# Run openssl inside container and return output
run_s_client() {
  local domain="$1"
  local port="$2"
  local group="$3"

  # Use /dev/null instead of echo pipe (more predictable)
  timeout "${TIMEOUT}" docker run --rm "${DOCKER_IMAGE}" sh -c \
    "openssl s_client -tls1_3 -groups '${group}' -connect '${domain}:${port}' -servername '${domain}' </dev/null 2>&1" \
    2>/dev/null || true
}

# Parse a value from openssl output
parse_cipher() {
  # Examples may vary, handle a few patterns
  awk '
    /New, TLSv1\.[23], Cipher is/ {print $NF; found=1}
    END {if(!found) print ""}
  '
}

parse_tls_ver() {
  awk '
    /Protocol  :/ {print $NF; found=1}
    END {if(!found) print ""}
  '
}

parse_server_temp_key() {
  awk '
    /^Server Temp Key:/ {
      $1=""; $2=""; $3=""; sub(/^ +/, "", $0); print; found=1
    }
    END {if(!found) print ""}
  '
}

parse_handshake_reason() {
  # classify common failure modes
  local out="$1"
  if echo "$out" | grep -qiE "Connection refused|connect:errno|timed out|No route to host|Temporary failure"; then
    echo "connection_failed"
  elif echo "$out" | grep -qiE "no protocols available|wrong version number|alert protocol version"; then
    echo "protocol_mismatch"
  elif echo "$out" | grep -qiE "handshake failure|alert handshake failure"; then
    echo "handshake_failure"
  elif echo "$out" | grep -qiE "Call to SSL_CONF_cmd\(-groups,"; then
    echo "bad_group_name"
  else
    echo "unsupported_or_unknown"
  fi
}

ensure_prereqs() {
  [ -f "$DOMAINS_FILE" ] || die "Domains file '$DOMAINS_FILE' not found."
  command -v docker >/dev/null 2>&1 || die "Docker is not installed or not in PATH."

  mkdir -p "$OUTPUT_DIR"
}

show_supported_groups_hint() {
  echo -e "${CYAN}[*] Available MLKEM groups in the Docker image:${NC}"
  docker run --rm "${DOCKER_IMAGE}" sh -c "openssl list -groups | grep -i mlkem | head -50" 2>/dev/null || true
  echo ""
}

# --- Main ---
ensure_prereqs

echo -e "${CYAN}[*] Ensuring Docker image is available...${NC}"
docker pull "${DOCKER_IMAGE}" >/dev/null 2>&1 || true

TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
REPORT_FILE="${OUTPUT_DIR}/pqc_scan_${TIMESTAMP}.csv"

# CSV header
echo "domain,port,group,supported,cipher,tls_version,server_temp_key,reason" > "$REPORT_FILE"

# Count domains (ignore blank lines and comments)
TOTAL_DOMAINS="$(grep -cve '^\s*$\|^\s*#' "$DOMAINS_FILE" 2>/dev/null || echo 0)"
TOTAL_GROUPS="${#KEM_GROUPS[@]}"
TOTAL_TESTS="$((TOTAL_DOMAINS * TOTAL_GROUPS))"

echo ""
echo "========================================================"
echo " PQC KEM Scanner (Docker: ${DOCKER_IMAGE})"
echo "========================================================"
echo -e " Domains:    ${CYAN}${TOTAL_DOMAINS}${NC} (from $DOMAINS_FILE)"
echo -e " Groups:     ${CYAN}${TOTAL_GROUPS}${NC}"
echo -e " Total tests:${CYAN} ${TOTAL_TESTS}${NC}"
echo -e " Delay:      ${DELAY}s between tests"
echo -e " Timeout:    ${TIMEOUT}s per test"
echo -e " Report:     ${REPORT_FILE}"
echo "========================================================"
echo ""

# Optional: show groups available in the image (helps avoid bad group names)
show_supported_groups_hint

# Debug: confirm the array values are really strings (prevents your "1000/20/24" issue)
echo -e "${CYAN}[*] Groups to test:${NC}"
for g in "${KEM_GROUPS[@]}"; do echo "  - $g"; done
echo ""

COUNT=0

parse_negotiated_group() {
  awk -F': ' '
    /Negotiated TLS1\.3 group:/ { print $2; found=1 }
    END { if(!found) print "" }
  ' | xargs
}

while IFS= read -r raw || [ -n "$raw" ]; do
  raw="$(trim "$raw")"
  [[ -z "$raw" || "$raw" =~ ^# ]] && continue

  domain="$raw"
  port="$PORT_DEFAULT"

  # support domain:port lines
  if [[ "$domain" == *":"* ]]; then
    port="${domain##*:}"
    domain="${domain%%:*}"
  fi

  domain="$(trim "$domain")"
  port="$(trim "$port")"

  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${CYAN}[*] Testing: ${domain}:${port}${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

  for group in "${KEM_GROUPS[@]}"; do
    COUNT=$((COUNT + 1))
    printf "  [%d/%d] %-18s " "$COUNT" "$TOTAL_TESTS" "$group"

    OUT="$(run_s_client "$domain" "$port" "$group")"
    CIPHER="$(echo "$OUT" | parse_cipher)"
    TLS_VER="$(echo "$OUT" | parse_tls_ver)"
    NEG_GROUP="$(echo "$OUT" | parse_negotiated_group)"
    SERVER_KEY="$(echo "$OUT" | parse_server_temp_key)"
    REASON="$(parse_handshake_reason "$OUT")"

    # Supported = TLS 1.3 handshake + cipher selected AND server temp key matches group (best signal)
  if [[ -n "$CIPHER" && "$CIPHER" != "(NONE)" ]]; then
    if [[ -n "$NEG_GROUP" && "$NEG_GROUP" == "$group" ]]; then
      echo -e "${GREEN}✓ SUPPORTED${NC}  cipher=${CIPHER}  negotiated=${NEG_GROUP}"
      echo "${domain},${port},${group},YES,${CIPHER},${TLS_VER},\"${NEG_GROUP}\"," >> "$REPORT_FILE"

    elif [[ -n "$NEG_GROUP" ]]; then
      # Handshake succeeded but server negotiated a different group (fallback or different preference)
      echo -e "${YELLOW}! Handshake OK (fallback)${NC}  cipher=${CIPHER}  negotiated=${NEG_GROUP}"
      echo "${domain},${port},${group},MAYBE,${CIPHER},${TLS_VER},\"${NEG_GROUP}\",negotiated_${NEG_GROUP}" >> "$REPORT_FILE"

    else
      # Handshake succeeded but we couldn't extract negotiated group; keep old temp key as a hint
      if echo "$SERVER_KEY" | grep -qi "$group"; then
        echo -e "${GREEN}✓ SUPPORTED${NC}  cipher=${CIPHER}  key=${SERVER_KEY}"
        echo "${domain},${port},${group},YES,${CIPHER},${TLS_VER},\"${SERVER_KEY}\"," >> "$REPORT_FILE"
      else
        echo -e "${YELLOW}! Handshake OK (no group info)${NC}  cipher=${CIPHER}  key=${SERVER_KEY}"
        echo "${domain},${port},${group},MAYBE,${CIPHER},${TLS_VER},\"${SERVER_KEY}\",no_negotiated_group" >> "$REPORT_FILE"
      fi
    fi

  else
    # Not supported / error
    if [[ "$REASON" == "connection_failed" ]]; then
      echo -e "${YELLOW}? Connection error${NC}"
      echo "${domain},${port},${group},ERROR,,,\"\",${REASON}" >> "$REPORT_FILE"
    else
      echo -e "${RED}✗ Not supported${NC} (${REASON})"
      echo "${domain},${port},${group},NO,,,\"\",${REASON}" >> "$REPORT_FILE"
    fi
  fi

    sleep "$DELAY"
  done

  echo ""
done < "$DOMAINS_FILE"

# --- Summary ---
SUPPORTED="$(grep -c ",YES," "$REPORT_FILE" 2>/dev/null || echo 0)"
MAYBE="$(grep -c ",MAYBE," "$REPORT_FILE" 2>/dev/null || echo 0)"
NOT_SUPPORTED="$(grep -c ",NO," "$REPORT_FILE" 2>/dev/null || echo 0)"
ERRORS="$(grep -c ",ERROR," "$REPORT_FILE" 2>/dev/null || echo 0)"

echo ""
echo "========================================================"
echo " Scan Complete"
echo "========================================================"
echo -e " ${GREEN}Supported:     ${SUPPORTED}${NC}"
echo -e " ${YELLOW}Maybe:         ${MAYBE}${NC} (handshake OK but key mismatch)"
echo -e " ${RED}Not supported: ${NOT_SUPPORTED}${NC}"
echo -e " ${YELLOW}Errors:        ${ERRORS}${NC}"
echo ""
echo -e "Full report saved to: ${CYAN}${REPORT_FILE}${NC}"
echo ""

