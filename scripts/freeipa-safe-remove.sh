#!/usr/bin/env bash
set -euo pipefail

fqdn="${FREEIPA_FQDN:-ipa1.ipa.pilot.internal}"
# Filesystem state under /etc|var/lib|var/log/dirsrv/ uses the "slapd-"
# prefix, but systemd's dirsrv@<instance>.service does NOT — stopping
# "dirsrv@slapd-X.service" silently no-ops on a unit that doesn't exist and
# leaves the real dirsrv instance running (and holding ports 389/636).
instance="${FREEIPA_DSRV_INSTANCE:-slapd-IPA-PILOT-INTERNAL}"
apply=0

usage() {
  cat <<'EOF'
Usage: freeipa-safe-remove.sh [--apply] [--fqdn FQDN] [--instance DS_INSTANCE]

Dry-run by default. Use --apply to actually stop services and remove residual
FreeIPA state from a test host.
EOF
}

log() {
  printf '%s\n' "$*"
}

run() {
  if (( apply )); then
    log "+ $*"
    "$@"
  else
    log "[dry-run] $*"
  fi
}

stop_disable_unit() {
  local unit="$1"
  # No existence pre-check: template-instantiated units (dirsrv@X.service,
  # pki-tomcatd@pki-tomcat.service) have no unit *file* of their own — only
  # the template (dirsrv@.service) does — so `systemctl list-unit-files
  # "$unit"` never matches them and would silently skip stopping a live
  # instance. Each call below already tolerates a missing/inactive unit.
  run systemctl stop "$unit" || true
  run systemctl disable "$unit" || true
  run systemctl reset-failed "$unit" || true
}

remove_path() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    run rm -rf -- "$path"
  fi
}

remove_hosts_pin() {
  local escaped
  escaped="${fqdn//./\\.}"
  if grep -Eq "[[:space:]]${escaped}([[:space:]]|$)" /etc/hosts; then
    if (( apply )); then
      local tmp
      tmp="$(mktemp)"
      awk -v fqdn="$fqdn" 'index($0, fqdn) == 0 { print }' /etc/hosts > "$tmp"
      cat "$tmp" > /etc/hosts
      rm -f "$tmp"
      log "+ removed /etc/hosts pin for ${fqdn}"
    else
      log "[dry-run] remove /etc/hosts pin for ${fqdn}"
    fi
  fi
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      apply=1
      ;;
    --fqdn)
      fqdn="${2:?missing value for --fqdn}"
      shift
      ;;
    --instance)
      instance="${2:?missing value for --instance}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

service_instance="${instance#slapd-}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  printf 'Run this script as root (or via sudo).\n' >&2
  exit 1
fi

log "FreeIPA safe remove"
log "  fqdn=${fqdn}"
log "  instance=${instance}"
log "  mode=$([[ $apply -eq 1 ]] && echo apply || echo dry-run)"

# Prefer the vendor uninstall path first. It can fail on partial installs, so we
# keep going with targeted cleanup below.
if command -v ipa-server-install >/dev/null 2>&1; then
  run ipa-server-install --uninstall -U || true
fi

# Stop and disable the known units that can keep ports or state files busy.
stop_disable_unit ipa.service
stop_disable_unit ipa-custodia.service
stop_disable_unit "dirsrv@${service_instance}.service"
stop_disable_unit pki-tomcatd@pki-tomcat.service
stop_disable_unit krb5kdc.service

# certmonger is a persistent daemon untouched by the service stops above, so
# tracking requests from a prior attempt (for cert/key files and NSS
# databases we're about to wipe below) survive and make the next install
# fail with "certmonger.duplicate: Certificate at same location is already
# used by request with nickname '<X>'". A fresh host has nothing tracked
# anyway, so clearing everything certmonger knows about is safe.
if command -v getcert >/dev/null 2>&1; then
  while IFS= read -r req_id; do
    [[ -n "$req_id" ]] || continue
    run getcert stop-tracking -i "$req_id" || true
  done < <(getcert list | sed -n "s/^Request ID '\(.*\)':$/\1/p")
fi

# Remove the host pin that FreeIPA install writes.
remove_hosts_pin

# Remove known FreeIPA state and partial-install residue.
for path in \
  /etc/ipa/default.conf \
  /etc/ipa/default.conf.ipabkp \
  /etc/ipa/ca.crt \
  /etc/ipa/custodia \
  /var/lib/ipa/.pilot-freeipa-installed \
  /var/lib/ipa/ra-agent.key \
  /var/lib/ipa/ra-agent.pem \
  /var/lib/ipa/pki-ca \
  /var/lib/ipa-client/pki \
  /var/lib/ipa-client/sysrestore \
  /var/lib/ipa/sysrestore \
  /var/lib/ipa/sysupgrade \
  "/etc/dirsrv/${instance}" \
  "/var/lib/dirsrv/${instance}" \
  "/var/log/dirsrv/${instance}" \
  "/dev/shm/${instance}" \
  "/etc/systemd/system/dirsrv@${service_instance}.service.d" \
  "/etc/systemd/system/multi-user.target.wants/dirsrv@${service_instance}.service" \
  /var/lib/pki/pki-tomcat \
  /etc/pki/pki-tomcat \
  /etc/sysconfig/pki/tomcat/pki-tomcat \
  /var/log/pki/pki-tomcat \
  /root/.dogtag \
  /root/ca-agent.p12 \
  /root/cacert.p12
do
  remove_path "$path"
done

# systemd auto-prunes a unit's ".wants" directory once the last symlink in it
# is removed — the "disable pki-tomcatd@..." call above does exactly that.
# Dogtag's own CA installer recreates its enablement symlink with a raw
# os.symlink() (not `systemctl enable`), so it assumes this directory already
# exists and crashes with FileNotFoundError on the next install if it doesn't.
if (( apply )); then
  mkdir -p /etc/systemd/system/pki-tomcatd.target.wants
else
  log "[dry-run] mkdir -p /etc/systemd/system/pki-tomcatd.target.wants"
fi

# Stopping/disabling dirsrv above does not clear systemd's "loaded" cache for
# a template-instantiated unit while its drop-in dir / enablement symlink
# still exist — and if it's left registered, ipa-server-install's own
# pre-flight check (lib389 assert_c) refuses to retry with "Another instance
# named '<X>' may already exist" even though nothing is actually running.
run systemctl daemon-reload || true

log "Done. Re-run the playbook only after verifying the host is quiet:"
log "  systemctl status ipa.service krb5kdc.service pki-tomcatd@pki-tomcat.service"
