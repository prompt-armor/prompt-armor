#!/bin/bash
# prompt-armor analyze wrapper for OpenClaw
# Usage: ./scripts/analyze.sh "text to analyze"
#        ./scripts/analyze.sh --file /path/to/file.txt
#
# Returns JSON with risk_score, decision, categories, evidence.
# Exit codes: 0=allow, 1=warn, 2=block, 3=error

set -euo pipefail

if ! command -v prompt-armor &> /dev/null; then
    echo '{"error": "prompt-armor not installed. Run: pip install prompt-armor"}' >&2
    exit 3
fi

prompt-armor analyze --json "$@"
