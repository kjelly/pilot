#!/usr/bin/env bash
# Install issue-to-pr Skill and native roles for Codex, Claude Code, and Antigravity.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: bash scripts/install.sh [--global | --project /path/to/git/repo] [--force] [--copy]

  --global         Install for the user across projects (default)
  --project DIR    Install inside that existing Git project
  --force          Backup and replace conflicting existing installs
  --copy           Copy instead of symbolic-linking aliases
  --help           Show this help

Global skill targets:
  ~/.agents/skills/issue-to-pr                      Codex
  ~/.claude/skills/issue-to-pr                       Claude Code
  ~/.gemini/antigravity-cli/skills/issue-to-pr       agy CLI
  ~/.gemini/config/skills/issue-to-pr                Antigravity App / IDE
Native agents are installed in .codex/agents, .claude/agents, and .gemini/config/agents.

Requires bash, git, python3. Actual PR execution also requires authenticated gh CLI.
HELP
}

mode=global
project=''
force=0
copy=0
while (( $# )); do
  case "$1" in
    --global) mode=global; shift ;;
    --project) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; mode=project; project=$2; shift 2 ;;
    --force) force=1; shift ;;
    --copy) copy=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unexpected option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null || { echo 'python3 is required' >&2; exit 2; }
command -v git >/dev/null || { echo 'git is required' >&2; exit 2; }
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ -f "$source_root/SKILL.md" ]] || { echo 'Incomplete installation archive: SKILL.md missing' >&2; exit 2; }

if [[ "$mode" == 'global' ]]; then
  base=$HOME
  canonical="$base/.agents/skills/issue-to-pr"
  aliases=("$base/.claude/skills/issue-to-pr"
           "$base/.gemini/antigravity-cli/skills/issue-to-pr"
           "$base/.gemini/config/skills/issue-to-pr")
  agents=("$base/.codex/agents|codex" "$base/.claude/agents|claude" "$base/.gemini/config/agents|agy")
else
  [[ -d "$project" ]] || { echo "Project not found: $project" >&2; exit 2; }
  base=$(git -C "$project" rev-parse --show-toplevel) || { echo 'Project is not a git checkout' >&2; exit 2; }
  canonical="$base/.agents/skills/issue-to-pr"
  aliases=("$base/.claude/skills/issue-to-pr")
  agents=("$base/.codex/agents|codex" "$base/.claude/agents|claude" "$base/.agents/agents|agy")
fi

same() {
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
    if same "$source" "$dest" || diff -qr -- "$source" "$dest" >/dev/null 2>&1; then
      echo "KEEP: $dest"; return
    fi
    if [[ $force -ne 1 ]]; then
      echo "Conflict at $dest. Add --force to back up and replace." >&2; exit 3
    fi
    backup "$dest"
  fi
  cp -R -- "$source" "$dest"
  echo "INSTALLED: $dest"
}

install_alias() {
  local target=$1 dest=$2 relative
  mkdir -p "$(dirname "$dest")"
  if [[ -e "$dest" || -L "$dest" ]]; then
    if same "$target" "$dest" && { [[ $copy -eq 0 ]] || [[ ! -L "$dest" ]]; }; then
      echo "KEEP: $dest"; return
    fi
    if [[ $force -ne 1 ]]; then
      echo "Conflict at $dest. Add --force to back up and replace." >&2; exit 3
    fi
    backup "$dest"
  fi
  if [[ $copy -eq 1 ]]; then
    cp -R -- "$target" "$dest"
    echo "COPIED: $dest"
  else
    relative=$(python3 -c 'import os,sys; print(os.path.relpath(sys.argv[1],sys.argv[2]))' "$target" "$(dirname "$dest")")
    ln -s -- "$relative" "$dest"
    echo "LINKED: $dest"
  fi
}

install_agent() {
  local source=$1 dest=$2
  mkdir -p "$(dirname "$dest")"
  if [[ -e "$dest" || -L "$dest" ]]; then
    if [[ -f "$dest" ]] && cmp -s -- "$source" "$dest"; then
      echo "KEEP: $dest"; return
    fi
    if [[ $force -ne 1 ]]; then
      echo "Conflict at $dest. Add --force to back up and replace." >&2; exit 3
    fi
    backup "$dest"
  fi
  cp -- "$source" "$dest"
  echo "AGENT: $dest"
}

install_dir "$source_root" "$canonical"
for dest in "${aliases[@]}"; do install_alias "$canonical" "$dest"; done
for spec in "${agents[@]}"; do
  directory=${spec%|*}; platform=${spec#*|}
  for role in issue-sa issue-coder issue-reviewer; do
    if [[ "$platform" == 'codex' ]]; then ext=toml; else ext=md; fi
    install_agent "$canonical/platforms/$platform/agents/$role.$ext" "$directory/$role.$ext"
  done
done

echo 'Installed issue-to-pr (Draft PR first; Ready only when mergeable). Restart or refresh your agents if needed.'
echo 'Next: run gh auth status, then invoke $issue-to-pr (Codex) or /issue-to-pr (Claude/agy).'
