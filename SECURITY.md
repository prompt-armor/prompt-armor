# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in prompt-armor, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@prompt-armor.dev** (or open a private security advisory on GitHub).

Include:
- Description of the vulnerability
- Steps to reproduce
- Expected vs actual behavior
- Impact assessment

We will respond within 48 hours and work with you on a fix before public disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Scope

Security issues in the following areas are in scope:
- Bypass techniques that evade all 4 analysis layers
- Denial of service via crafted inputs
- Model supply chain attacks (compromised ONNX models)
- Information leakage through the analysis pipeline
- Vulnerabilities in the MCP server

## Known Limitations

prompt-armor is a defense-in-depth layer, not a complete security solution:
- Single-prompt analysis only (no multi-turn session tracking)
- ~19ms latency adds a small overhead to each request
- L2 classifier requires model download (~83MB) for full accuracy
- Non-English detection is available for DE, ES, FR, PT; other languages have limited coverage
