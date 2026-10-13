#!/usr/bin/env bash
set -euo pipefail

# deploy/reconcile intentionally reject non-TTY callers even in --actions
# mode. util-linux script(1) creates that PTY. Its --command path is a shell
# string on this host, however, so do not interpolate action argv into it:
# hand the exact NUL-delimited argv to this wrapper's child mode instead.
if [[ ${1:-} == --exec-argv ]]; then
  [[ $# == 2 ]] || { echo 'run-in-pty child received invalid argv handoff' >&2; exit 2; }
  mapfile -d '' -t argv < "$2"
  (( ${#argv[@]} > 0 )) || { echo 'run-in-pty child received an empty argv' >&2; exit 2; }
  exec "${argv[@]}"
fi

(( $# > 0 )) || { echo 'run-in-pty requires a command' >&2; exit 2; }
command -v script >/dev/null || { echo 'run-in-pty requires util-linux script(1)' >&2; exit 127; }

argv_file=$(mktemp "${TMPDIR:-/tmp}/hufu-pty-argv.XXXXXX")
trap 'rm -f -- "$argv_file"' EXIT HUP INT TERM
printf '%s\0' "$@" >"$argv_file"

# Child output already goes to stdout. A second log at /dev/stdout duplicates
# every byte when the caller captures a pipe, creating empty PLAY RECAP blocks.
# Discard script's separate transcript; the caller owns the complete phase log.
set +e
HUFU_PTY_WRAPPER=${BASH_SOURCE[0]} HUFU_PTY_ARGV_FILE=$argv_file SHELL=/bin/bash \
  script --quiet --flush --return --command 'exec "$HUFU_PTY_WRAPPER" --exec-argv "$HUFU_PTY_ARGV_FILE"' /dev/null
status=$?
set -e
exit "$status"
