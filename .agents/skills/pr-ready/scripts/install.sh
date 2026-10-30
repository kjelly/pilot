#!/usr/bin/env bash
# Installs one cross-platform Agent Skill and the native SA/Coder/Reviewer agents.
# Bash + Python 3; designed for Linux/macOS/WSL. Does not modify Codex/Claude/agy settings files.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: bash scripts/install.sh [--global | --project PATH] [--force] [--copy]

  --global          Install for the current user across repositories (default)
  --project PATH    Install to an existing Git repository, for all three agents
  --force           Replace an existing managed skill/agent file (back it up first)
  --copy            Copy aliases instead of symlinks (use if symlinks unsupported)
  --help            Print help

Codex:       ~/.agents/skills/pr-ready or REPO/.agents/skills/pr-ready
Claude Code: ~/.claude/skills/pr-ready or REPO/.claude/skills/pr-ready
agy CLI:     ~/.gemini/antigravity-cli/skills/pr-ready or REPO/.agents/skills/pr-ready
agy App:     ~/.gemini/config/skills/pr-ready or REPO/.agents/skills/pr-ready

Includes native agent definitions in the matching global/project agent directories.
HELP
}

mode=global
project=''
force=0
copy=0
while (($#)); do
  case "$1" in
    --global) mode=global; shift ;;
    --project) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; mode=project; project=$2; shift 2 ;;
    --force) force=1; shift ;;
    --copy) copy=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v python3 >/dev/null || { echo 'python3 required' >&2; exit 2; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ -f "$root/SKILL.md" ]] || { echo 'SKILL.md missing in bundle' >&2; exit 2; }

if [[ "$mode" == global ]]; then
  base="$HOME"
  canonical="$base/.agents/skills/pr-ready"
  aliases=("$base/.claude/skills/pr-ready"
           "$base/.gemini/antigravity-cli/skills/pr-ready"
           "$base/.gemini/config/skills/pr-ready")
  agents=("$base/.codex/agents|codex" "$base/.claude/agents|claude" "$base/.gemini/config/agents|agy")
else
  [[ -d "$project" ]] || { echo 'Project path missing' >&2; exit 2; }
  base=$(cd "$project" && git rev-parse --show-toplevel) || { echo 'Expected Git repository' >&2; exit 2; }
  canonical="$base/.agents/skills/pr-ready"
  aliases=("$base/.claude/skills/pr-ready")
  agents=("$base/.codex/agents|codex" "$base/.claude/agents|claude" "$base/.agents/agents|agy")
fi

same_path() {
  [[ "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1")" == \
     "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$2")" ]]
}

backup() {
  local dest=$1 suffix
  suffix=$(date +%Y%m%d%H%M%S)
  local bak="$dest.backup-$suffix"
  local n=0
  while [[ -e "$bak" || -L "$bak" ]]; do n=$((n+1)); bak="$dest.backup-$suffix-$n"; done
  mv -- "$dest" "$bak"
  echo "BACKUP: $bak"
}

install_dir() {
  local source=$1 dest=$2
  mkdir -p "$(dirname "$dest")"
  if [[ -e "$dest" || -L "$dest" ]]; then
    if same_path "$source" "$dest" || diff -qr -- "$source" "$dest" >/dev/null 2>&1; then
      echo "KEEP (unchanged): $dest"
      return
    fi
    if [[ $force != 1 ]]; then
      echo "Conflict: $dest exists. Re-run with --force to replace it." >&2
      exit 3
    fi
    backup "$dest"
  fi
  cp -R -- "$source" "$dest"
  echo "INSTALLED: $dest"
}

install_alias() {
  local target=$1 dest=$2
  mkdir -p "$(dirname "$dest")"
  if [[ -e "$dest" || -L "$dest" ]]; then
    if same_path "$target" "$dest" && { [[ $copy -eq 0 ]] || [[ ! -L "$dest" ]]; }; then
      echo "KEEP: $dest"
      return
    fi
    if [[ $force != 1 ]]; then
      echo "Conflict: $dest exists. Re-run with --force to replace it." >&2
      exit 3
    fi
    backup "$dest"
  fi
  if [[ $copy == 1 ]]; then
    cp -R -- "$target" "$dest"
  else
    local relative
    relative=$(python3 -c 'import os,sys; print(os.path.relpath(sys.argv[1],sys.argv[2]))' "$target" "$(dirname "$dest")")
    ln -s -- "$relative" "$dest"
  fi
  echo "LINKED: $dest"
}

install_agent() {
  local source=$1 dest=$2
  mkdir -p "$(dirname "$dest")"
  if [[ -e "$dest" || -L "$dest" ]]; then
    if [[ -f "$dest" ]] && cmp -s -- "$source" "$dest"; then
      echo "KEEP: $dest"
      return
    fi
    if [[ $force != 1 ]]; then
      echo "Conflict: $dest exists and differs. Use --force to back it up and replace it." >&2
      exit 3
    fi
    backup "$dest"
  fi
  cp -- "$source" "$dest"
  echo "AGENT: $dest"
}

install_dir "$root" "$canonical"
for alias in "${aliases[@]}"; do install_alias "$canonical" "$alias"; done
for spec in "${agents[@]}"; do
  directory=${spec%|*}
  platform=${spec#*|}
  for role in pr-sa pr-coder pr-reviewer; do
    case "$platform" in codex) ext=toml ;; *) ext=md ;; esac
    install_agent "$canonical/platforms/$platform/agents/$role.$ext" "$directory/$role.$ext"
  done
done
printf '\nInstallation complete. Restart the CLI if the skill is not discovered immediately.\n'
printf 'Prerequisites for actual PR actions: git, gh (authenticated), python3, and write access to PR branch.\n'
