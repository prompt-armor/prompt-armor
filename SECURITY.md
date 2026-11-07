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
| 0.6.x   | Yes       |
| 0.5.x   | No        |
| 0.1.x   | No        |

## Scope

Security issues in the following areas are in scope:
- Bypass techniques that evade all 5 analysis layers
- Denial of service via crafted inputs
- Model supply chain attacks (compromised ONNX models)
- Information leakage through the analysis pipeline
- Vulnerabilities in the MCP server

## Known Limitations

prompt-armor is a defense-in-depth layer, not a complete security solution:
- Session tracking via inflammation cascade (opt-in, single engine instance)
- ~17ms average latency (Apple M4; median ~6ms; ~54ms on a 4-vCPU CI runner) adds a small overhead to each request
- Council mode sends prompts to local LLM (ollama) — configure `privacy_mode: truncated` for API providers
- L2 classifier requires a one-time model download (~270MB) for full accuracy; without it L2 runs a keyword fallback and logs a degraded-layer warning
- Non-English: false positives and detection are measured for PT, ES, DE and FR against English in CI (`tests/benchmark/run_language_parity.py`); L2 was trained on 30 languages, but L1's rules cover only EN, DE, ES, FR and PT, and other languages are not measured
