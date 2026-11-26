# Security Policy

## Supported Versions

Only the latest state of the `main` branch is actively maintained and supported with security updates.

| Branch / Version | Supported |
| ---------------- | --------- |
| `main`           | Yes       |
| Older commits    | No        |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities, exposed Okta tenant URLs, private key material, PII leakage bugs, or prompt-injection bypasses through public GitHub Issues or Pull Requests.

Instead, report vulnerabilities privately via one of the following channels:

1. **GitHub Private Vulnerability Reporting:** Use the **Report a vulnerability** button under the **Security** tab of `apensabene/okta-log-agent`.
2. **Direct Contact:** Email **apensabene@pm.me** with the subject line `[SECURITY] okta-log-agent - <Brief Summary>`.

### What to Include
* Description of the issue and affected component(s) (OAuth `private_key_jwt` auth flow, MCP server/tool handlers, PII scrubbing logic, or audit logger)
* Potential impact (e.g., unauthorized Okta API scope escalation, PII exposure in `agent_audit.log`, or prompt injection)
* Steps to reproduce or suggested remediation

### Response Timeline
* **Initial Acknowledgment:** Within 48 hours
* **Triage & Remediation Assessment:** Within 5 business days

## Security Architecture & Baseline Controls

This repository enforces the following security practices:
* **Zero Static API Tokens:** Authenticates to Okta Identity Engine exclusively via short-lived OAuth 2.0 `private_key_jwt` (RS256) assertions—no static SSWS API tokens are used.
* **Read-Only Least-Privilege Scopes:** Scoped strictly to read-only telemetry permissions (`okta.logs.read`, `okta.users.read`, `okta.apps.read`) with no administrative write access.
* **Deterministic PII Minimization & Auditability:** Scrubs personally identifiable information prior to LLM processing and records tool invocations to `agent_audit.log` while excluding private keys (`.pem`) and `.env` files via `.gitignore`.
