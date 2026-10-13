#!/usr/bin/env bash

# Source this file from a launcher after changing to the subject project root.
# It deliberately resolves Hufu from runtime inputs instead of knowing where a
# particular checkout lives.

resolve_hufu_command() {
  HUFU_COMMAND=()
  HUFU_TEMP_DIR=""

  if [[ -n "${HUFU_BIN:-}" ]]; then
    local requested_bin="$HUFU_BIN"
    if [[ "$requested_bin" == */* ]]; then
      if [[ ! -x "$requested_bin" ]]; then
        printf 'HUFU_BIN is not executable: %s\n' "$requested_bin" >&2
        return 1
      fi
      HUFU_COMMAND=("$requested_bin")
      return 0
    fi
    if ! requested_bin="$(command -v -- "$requested_bin")"; then
      printf 'HUFU_BIN was not found on PATH: %s\n' "$HUFU_BIN" >&2
      return 1
    fi
    HUFU_COMMAND=("$requested_bin")
    return 0
  fi

  if [[ -n "${HUFU_ROOT:-}" && -f "$HUFU_ROOT/go.mod" && -d "$HUFU_ROOT/cmd/hufu" ]]; then
    HUFU_TEMP_DIR="$(mktemp -d)"
    if ! (cd "$HUFU_ROOT" && go build -o "$HUFU_TEMP_DIR/hufu" ./cmd/hufu); then
      printf 'Failed to build Hufu from HUFU_ROOT: %s\n' "$HUFU_ROOT" >&2
      return 1
    fi
    HUFU_COMMAND=("$HUFU_TEMP_DIR/hufu")
    return 0
  fi

  if command -v hufu >/dev/null 2>&1; then
    HUFU_COMMAND=("$(command -v hufu)")
    return 0
  fi

  printf '%s\n' 'Hufu was not found. Install `hufu`, set HUFU_BIN, or set HUFU_ROOT to a Hufu checkout.' >&2
  return 1
}

cleanup_hufu_command() {
  if [[ -n "${HUFU_TEMP_DIR:-}" ]]; then
    rm -rf -- "$HUFU_TEMP_DIR"
    HUFU_TEMP_DIR=""
  fi
}
