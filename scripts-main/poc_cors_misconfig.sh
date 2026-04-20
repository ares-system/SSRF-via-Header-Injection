#!/bin/bash
# PoC: CORS Credentials + Wildcard Origin & Info Disclosure
# Severity: HIGH

TARGETS=("https://api.dune.com/api/v1/" "https://api.sim.dune.com/v1/")

echo -e "\033[0;34m[+] Starting CORS Misconfiguration Audit...\033[0m"

for URL in "${TARGETS[@]}"; do
    echo -e "\n\033[1;33mTesting Endpoint: $URL\033[0m"
    
    RESP=$(curl -s -i --max-time 5 "$URL" \
      -H "Origin: https://evil.com" \
      -H "Access-Control-Request-Method: GET" \
      -X OPTIONS)

    echo "$RESP" | grep -E "access-control|HTTP/" | head -10

    # Validation Logic
    if echo "$RESP" | grep -qi "access-control-allow-credentials: true" && \
       echo "$RESP" | grep -qi "access-control-allow-origin: \*"; then
        echo -e "\033[0;31m[!] VULNERABLE: Concurrent credentials:true and origin:* detected.\033[0m"
    fi

    # Check for leaked internal headers (F2)
    if echo "$RESP" | grep -qi "mcp-session"; then
        echo -e "\033[0;31m[!] INFO: Internal MCP headers exposed in Access-Control-Expose-Headers.\033[0m"
    fi
done
