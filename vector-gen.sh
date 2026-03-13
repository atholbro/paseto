#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$SCRIPT_DIR/gradlew" -p "$SCRIPT_DIR" :vector-gen:installDist </dev/null
exec "$SCRIPT_DIR/vector-gen/build/install/vector-gen/bin/vector-gen" "$@"
