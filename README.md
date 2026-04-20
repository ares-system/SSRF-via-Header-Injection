# SSRF via Header Injection Vulnerability

**Target:** `api.sim.dune.com`  
**Repository:** [duneanalytics/sim-proxy](https://github.com/duneanalytics/sim-proxy)  
**Severity:** High (Critical if escalated to internal infrastructure access)

## Overview

The `sim-proxy` service in Dune Analytics' infrastructure is vulnerable to Server-Side Request Forgery (SSRF) through arbitrary header injection. This vulnerability stems from "Blind Header Forwarding" where client-supplied headers are forwarded without sanitization, allowing attackers to manipulate proxy behavior and potentially access internal services.

## Vulnerability Details

### Root Cause
The application uses `Object.fromEntries(request.headers.entries())` to collect all client headers and forward them directly to upstream servers without any sanitization or allowlisting. This design flaw enables attackers to inject malicious headers including `Host`, `X-Forwarded-For`, and `X-Real-IP`.

### Impact
- **SSRF Attack Vector:** By manipulating the `Host` header, attackers can attempt to force the proxy to communicate with internal metadata services (e.g., AWS/GCP metadata endpoints at `169.254.169.254`)
- **Infrastructure Mapping:** Attackers can probe internal network services through the proxy
- **Security Bypass:** While Cloudflare provides perimeter defense, the core application logic is inherently unsafe and relies on third-party mitigations rather than secure coding practices

### Vulnerable Code Location
The vulnerable code is located at:  
`github.com/duneanalytics/sim-proxy/blob/main/src/index.ts` (line 41)

## Proof of Concept

### Prerequisites
- Terminal with `curl` installed
- Basic understanding of HTTP headers and SSRF attacks

### Reproduction Steps

1. **Execute the attack command:**
```bash
curl -v "https://api.sim.dune.com/v1/" \
  -H "Host: metadata.google.internal" \
  -H "X-Forwarded-For: http://169.254.169.254/latest/meta-data/"
```

2. **Analyze the output:**
   - Observe the verbose output (`-v` flag)
   - Even if blocked by WAF, the server's attempt to process the modified `Host` header confirms the vulnerability
   - Look for evidence of header forwarding in the response

### Automated Testing Script
A comprehensive testing script is available in this repository:
```bash
./scripts-main/poc_ssrf_header_injection.sh
```

## Technical Analysis

### Attack Mechanism
1. **Header Injection:** Client supplies arbitrary headers through HTTP requests
2. **Blind Forwarding:** `sim-proxy` forwards all headers without validation
3. **Upstream Impact:** Injected headers affect upstream server behavior
4. **SSRF Execution:** Modified `Host` header redirects requests to internal services

### Security Implications
- **Internal Service Discovery:** Attackers can map internal network services
- **Metadata Exposure:** Potential access to cloud provider metadata services
- **Lateral Movement:** Could serve as initial access point for broader attacks
- **Trust Boundary Violation:** Proxy violates trust boundaries between external and internal networks

## Mitigation Recommendations

### Immediate Actions
1. **Implement Header Allowlisting:** Only forward specific, known-safe headers
2. **Add Header Validation:** Reject headers containing internal IP addresses or metadata endpoints
3. **Deploy Request Sanitization:** Strip or normalize suspicious headers before forwarding

### Code-Level Fixes
```javascript
// Example: Safe header forwarding with allowlisting
const ALLOWED_HEADERS = ['user-agent', 'accept', 'content-type', 'authorization'];
const safeHeaders = {};
for (const [key, value] of request.headers.entries()) {
  if (ALLOWED_HEADERS.includes(key.toLowerCase())) {
    safeHeaders[key] = value;
  }
}
// Use safeHeaders instead of all headers
```

### Infrastructure Hardening
1. **Network Segmentation:** Isolate proxy services from internal networks
2. **Egress Filtering:** Restrict outbound connections from proxy servers
3. **Monitoring:** Implement alerting for suspicious header patterns

## References

- **Repository:** [SSRF-via-Header-Injection](https://github.com/ares-system/SSRF-via-Header-Injection.git)
- **Vulnerable Code:** [sim-proxy/src/index.ts](https://github.com/duneanalytics/sim-proxy/blob/main/src/index.ts)
- **Related Research:** See `PactNetwork_Security_Audit_Report.md` for additional security findings

## Disclosure Timeline

- **Discovery Date:** April 20, 2026
- **Report Date:** April 20, 2026
- **Status:** Actively monitored

## Responsible Disclosure
This vulnerability has been responsibly disclosed to the affected organization. The information is provided for educational purposes and to promote secure coding practices.

---

**Note:** This repository contains proof-of-concept scripts and documentation for security research purposes only. Use responsibly and only on systems you own or have explicit permission to test. 
