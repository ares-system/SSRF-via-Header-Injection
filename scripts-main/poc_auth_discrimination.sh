#!/bin/bash
# PoC: Authentication Discrimination (Bearer vs X-DUNE-API-KEY)
# Severity: LOW

DUNE_KEY="${DUNE_API_KEY:-ttoYaDYaUmeaGFpElT2RG2yieBcNbzeU}"
ENDPOINT_GET="https://api.dune.com/api/v1/queries/"
ENDPOINT_POST="https://api.dune.com/api/v1/execute/"

echo -e "\033[0;34m[+] Checking Authentication Middleware Consistency...\033[0m\n"

# Test Comparison
echo -n "Testing POST (Bearer): "
curl -s -o /dev/null -w "%{http_code}" -X POST "$ENDPOINT_POST" -H "Authorization: Bearer $DUNE_KEY" -H "Content-Type: application/json" -d '{"query_id":1}'

echo -e "\nTesting GET (Bearer):  "
curl -s -o /dev/null -w "%{http_code}" -G "$ENDPOINT_GET" -H "Authorization: Bearer $DUNE_KEY"

echo -e "\nTesting GET (X-DUNE):  "
curl -s -o /dev/null -w "%{http_code}" -G "$ENDPOINT_GET" -H "X-DUNE-API-KEY: $DUNE_KEY"

echo -e "\n\n\033[1;33m[Analysis]\033[0m"
echo "If HTTP Code different between Bearer (GET) and X-DUNE (GET), there's Auth Discrimination."
