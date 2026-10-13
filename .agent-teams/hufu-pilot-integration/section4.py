#!/usr/bin/env python3
"""Runbook §4 probes. Mutations run only inside the EXECUTE provider."""
import datetime
import json
import os
import secrets
import shlex
import subprocess
import time
import urllib.parse
import urllib.request
from workflow_contract import (checkpoint, PROJECT, HOSTS, SUDO_COMMAND, DRIFT_COMMAND,
                               run, remote, scenario, recap)

REQUIRED = {"4.1-alice-sshd", "4.1-alice-sudo", "4.1-bob-sshd", "4.1-alice-login",
            "4.1-alice-command", "4.1-alice-command-denied", "4.1-bob-login-denied",
            "4.1-bob-authenticated-denial", "4.2-node-targets", "4.2-log-coverage",
            "4.2-wazuh-labels", "4.3-fim", "4.3-nfs-mount", "4.4-revoked-hbac", "4.4-revoked-sudo-hbac", "4.4-revoked-login",
            "4.4-restored-login", "4.4-command-drift", "4.4-idempotency", "4.5-endpoint"}
for host in HOSTS:
    REQUIRED.update({f"4.2-marker-{host}", f"4.2-landing-{host}",
                     f"4.3-timer-{host}", f"4.3-snapshot-{host}",
                     f"4.5-ca-{host}", f"4.5-resolver-{host}", f"4.5-dns-{host}"})
for service in ("grafana", "prometheus", "loki", "thanos"):
    REQUIRED.add("4.2-ready-" + service)


class Checks:
    def __init__(self):
        self.root = checkpoint()
        self.facts = json.loads((self.root / "facts/topology-inventory.json").read_text())["hosts"]
        self.nexus = self.facts["nexus"]["ansible_host"]
        self.labels = {h: remote("hostname-" + h, h, "hostname -s") for h in HOSTS}
        self.fqdns = {h: remote("fqdn-" + h, h, "hostname -f") for h in HOSTS}
        self.output = self.root / "logs/section4.jsonl"

    def record(self, identifier, function):
        try:
            function()
            value = {"id": identifier, "status": "pass"}
        except Exception as error:
            value = {"id": identifier, "status": "fail", "detail": str(error)}
            with self.output.open("a") as stream:
                stream.write(json.dumps(value) + "\n")
            raise
        with self.output.open("a") as stream:
            stream.write(json.dumps(value) + "\n")

    def ipa(self, name, args):
        return remote(name, "freeipa-server", 'read -r password; printf "%s\\n" "$password" | kinit admin && ipa ' + args,
                      input_text=os.environ["PILOT_IPA_ADMIN_PASSWORD"] + "\n")

    def hbac(self, user, service, granted):
        out = self.ipa(f"hbac-{user}-{service}", f"hbactest --user={user} --host={self.fqdns['nexus']} --service={service}")
        require("Access granted: " + str(granted) in out, "HBAC decision mismatch")

    def ssh(self, name, user, command, allowed):
        env = dict(os.environ, SSHPASS=os.environ[f"PILOT_{user.upper()}_PASSWORD"])
        result = subprocess.run(["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "ControlMaster=no", "-o", "ConnectTimeout=10",
            "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
            f"{user}@{self.nexus}", command], env=env, text=True, capture_output=True, timeout=45, check=False)
        (self.root / "logs" / (name + ".log")).write_text(result.stdout + result.stderr)
        if allowed:
            require(result.returncode == 0, name + " did not succeed")
        else:
            require(result.returncode != 0, name + " unexpectedly succeeded")
            if command == "sudo -n cat /etc/shadow":
                require("not allowed" in result.stderr or "password is required" in result.stderr,
                        "sudo denial did not come from authorization")
            else:
                require(result.returncode == 255 and "Permission denied" in result.stderr,
                        "login failed for a reason other than authorization")

    def http(self, port, path, params=None):
        url = f"http://{self.nexus}:{port}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        with urllib.request.urlopen(url, timeout=20) as response:
            body = response.read().decode()
        return body

    def metrics(self):
        data = json.loads(self.http(10912, "/api/v1/query", {"query": 'up{job="node",site="site-nexus"}'}))
        results = data["data"]["result"]
        require(data["status"] == "success" and len(results) == 3, "expected three node targets")
        require({r["metric"]["instance"] for r in results} ==
                {f'{self.facts[h]["ansible_host"]}:9100' for h in HOSTS}, "node target identity mismatch")
        require(all(float(r["value"][1]) == 1 for r in results), "node target down")

    def authorization(self):
        for user, service, granted in (("alice", "sshd", True), ("alice", "sudo", True), ("bob", "sshd", False)):
            self.record(f"4.1-{user}-{service}", lambda u=user, s=service, g=granted: self.hbac(u, s, g))
        self.record("4.1-alice-login", lambda: self.ssh("alice-login", "alice", "true", True))
        self.record("4.1-alice-command", lambda: self.ssh("alice-sudo", "alice", "sudo -n " + SUDO_COMMAND, True))
        self.record("4.1-alice-command-denied", lambda: self.ssh("alice-denied-command", "alice", "sudo -n cat /etc/shadow", False))
        # A real Kerberos login independently proves Bob's personalized credential.
        remote("bob-credential", "freeipa-server", "kinit bob", input_text=os.environ["PILOT_BOB_PASSWORD"] + "\n")
        since = int(time.time())
        self.record("4.1-bob-login-denied", lambda: self.ssh("bob-denied", "bob", "true", False))
        def pam_denial():
            out = remote("bob-pam-denial", "nexus", f"journalctl -u ssh --since '@{since}' --no-pager")
            # Match a single sshd PID: unrelated successful logins cannot satisfy it.
            import re
            success = re.findall(r"sshd\[(\d+)\].*pam_sss\(sshd:auth\): authentication success.*user=bob", out)
            require(any(re.search(r"sshd\[" + pid + r"\].*pam_sss\(sshd:account\): Access denied for user bob", out)
                        for pid in success), "missing successful authentication followed by Bob's HBAC denial")
        self.record("4.1-bob-authenticated-denial", pam_denial)

    def observability(self):
        paths = {"grafana": (3000, "/api/health"), "prometheus": (9090, "/-/ready"),
                 "loki": (3100, "/ready"), "thanos": (10912, "/-/ready")}
        for name, (port, path) in paths.items():
            self.record("4.2-ready-" + name, lambda p=port, q=path: require(bool(self.http(p, q)), "empty readiness response"))
        self.record("4.2-node-targets", self.metrics)
        token = secrets.token_hex(8)
        for host in HOSTS:
            label = self.labels[host]
            command = f"test -s /var/log/siem/{label}/audit.log && test -s /var/log/siem/{label}/auth.log"
            self.record("4.2-landing-" + host, lambda c=command, h=host: remote("landing-" + h, "nexus", c))
            remote("marker-inject-" + host, host, "logger -p local6.info " + shlex.quote(f"PILOT-HUFU-{token}-{label}"))
        for host in HOSTS:
            label = self.labels[host]
            marker = f"PILOT-HUFU-{token}-{label}"
            def marker_visible(label=label, marker=marker):
                data = json.loads(self.http(3100, "/loki/api/v1/query_range",
                    {"query": '{job="pilot-siem",host="' + label + '"} |= "PILOT-HUFU-' + token + '"', "limit": 200}))
                streams = data["data"]["result"]
                lines = [line for stream in streams for _, line in stream["values"]]
                require(lines and all(marker in line for line in lines), "marker missing or wrong host attribution")
            self.record("4.2-marker-" + host, lambda f=marker_visible: poll(f))
        def coverage():
            data = json.loads(self.http(3100, "/loki/api/v1/query", {"query": 'sum by (host) (count_over_time({job="pilot-siem"}[5m]))'}))
            require({r["metric"].get("host") for r in data["data"]["result"] if float(r["value"][1]) > 0}
                    >= set(self.labels.values()), "raw log coverage incomplete")
        self.record("4.2-log-coverage", coverage)

    def backups_and_fim(self):
        def nfs_mount():
            out = remote('nfs-mount', 'client-vm', 'stat /sysops && findmnt -T /sysops -n -o FSTYPE,OPTIONS')
            require('nfs4' in out and 'sec=krb5' in out, 'NFS share not mounted with Kerberos security')
        self.record('4.3-nfs-mount', nfs_mount)
        for host in HOSTS:
            self.record("4.3-timer-" + host, lambda h=host: remote("timer-" + h, h,
                "systemctl is-active restic-backup.timer && systemctl is-enabled restic-backup.timer"))
            started = datetime.datetime.now(datetime.timezone.utc)
            remote("backup-trigger-" + host, host, "systemctl start restic-backup.service", timeout=900)
            def fresh_snapshot(h=host, start=started):
                out = remote("snapshot-" + h, h, ". /etc/pilot/restic-env; restic snapshots --json", timeout=120)
                values = json.loads(out)
                require(any(r["hostname"] == self.fqdns[h] and
                    datetime.datetime.fromisoformat(r["time"].replace("Z", "+00:00")) >= start for r in values),
                    "missing fresh snapshot for " + h)
            self.record("4.3-snapshot-" + host, fresh_snapshot)
        path = "/etc/pilot-hufu-fim-" + secrets.token_hex(8)
        remote("fim-create", "client-vm", "touch " + shlex.quote(path))
        try:
            def fim_alert():
                command = "container=$(docker ps --filter label=com.docker.compose.service=wazuh.manager --format '{{.Names}}'); "
                command += 'test -n "$container" && test "$(printf "%s\\n" "$container" | wc -l)" -eq 1 && '
                command += 'docker exec "$container" tail -n 2000 /var/ossec/logs/alerts/alerts.json'
                out = remote("fim-alert", "nexus", command)
                alerts = [json.loads(line) for line in out.splitlines() if line.strip()]
                require(any(a.get("agent", {}).get("name") == self.fqdns["client-vm"] and
                    a.get("syscheck", {}).get("path") == path and
                    a["syscheck"].get("event") == "added" and a["syscheck"].get("mode") == "whodata"
                    for a in alerts), "missing real-time whodata file-add alert")
            self.record("4.3-fim", lambda: poll(fim_alert, timeout=180))
        finally:
            remote("fim-cleanup", "client-vm", "rm -f -- " + shlex.quote(path))
        def alert_labels():
            data = json.loads(self.http(3100, "/loki/api/v1/query_range",
                {"query": '{job="pilot-siem-wazuh-alerts"}', "limit": 100}))
            streams = data["data"]["result"]
            require(streams and all(s["stream"].get("host") for s in streams), "Wazuh alert host labels missing")
        self.record("4.2-wazuh-labels", lambda: poll(alert_labels))

    def identity_cycle(self):
        def edit(name):
            run("cycle-edit-" + name, [str(PROJECT / "pilot"), "edit", "--dir", str(self.root),
                "--actions", str(self.root / "actions/cycle" / (name + ".json")),
                "--trace-out", str(self.root / "logs" / ("cycle-edit-" + name + ".jsonl"))])
            run("cycle-lint-" + name, [str(PROJECT / "pilot"), "roster", "lint", str(self.root / ".vault/ipa-identity.yaml")])
            return scenario("reconcile/freeipa-identity.json", "reconcile", "cycle-reconcile-" + name)
        recap(edit("revoke"))
        remote("revoke-cache", "nexus", "sss_cache -E && systemctl restart sssd")
        self.record("4.4-revoked-hbac", lambda: self.hbac("alice", "sshd", False))
        self.record("4.4-revoked-sudo-hbac", lambda: self.hbac("alice", "sudo", False))
        self.record("4.4-revoked-login", lambda: self.ssh("revoked-login", "alice", "true", False))
        recap(edit("restore"))
        remote("restore-cache", "nexus", "sss_cache -E && systemctl restart sssd")
        self.record("4.4-restored-login", lambda: self.ssh("restored-login", "alice", "true", True))
        self.record("4.4-command-drift", lambda: self.ssh("command-drift", "alice", "sudo -n " + DRIFT_COMMAND, True))
        self.record("4.4-idempotency", lambda: recap(scenario("reconcile/freeipa-identity.json", "reconcile", "cycle-idempotency"), idempotent=True))

    def endpoint(self):
        for host in HOSTS:
            ca = "f=/usr/local/share/ca-certificates/pilot-freeipa-ca.crt; test -f \"$f\" || f=/etc/pki/ca-trust/source/anchors/pilot-freeipa-ca.crt; "
            ca += 'test -f "$f" && openssl verify "$f" && test "$(openssl x509 -in "$f" -noout -issuer | sed s/issuer=//)" = "$(openssl x509 -in "$f" -noout -subject | sed s/subject=//)"'
            self.record("4.5-ca-" + host, lambda h=host, c=ca: remote("ca-" + h, h, c))
            resolver = "if command -v nmcli >/dev/null; then conn=$(nmcli -t -f NAME connection show --active | sed -n '1p'); "
            resolver += 'test "$(nmcli -g ipv4.ignore-auto-dns connection show "$conn")" = yes; '
            resolver += "else grep -q pilot-freeipa-dns-client /etc/resolv.conf; fi"
            self.record("4.5-resolver-" + host, lambda h=host, c=resolver: remote("resolver-" + h, h, c))
            def dns(h=host):
                out = remote("dns-" + h, h, "getent hosts grafana.it.pilot.internal")
                require(out.split()[0] == self.nexus, "endpoint resolves to wrong address")
                for record in ('grafana', 'wazuh', 'thanos'):
                    out = remote("dns-authority-" + h + '-' + record, h,
                        "dig +short @" + self.facts["freeipa-server"]["ansible_host"] +
                        " " + record + ".it.pilot.internal A")
                    require(out.strip() == self.nexus, "authoritative DNS address mismatch for " + record)
            self.record("4.5-dns-" + host, dns)
        def health():
            out = remote("endpoint-health", "client-vm", "curl --fail --max-time 20 -sS https://grafana.it.pilot.internal/api/health")
            require(json.loads(out).get("database") == "ok", "Grafana database unhealthy")
            out = remote("endpoint-certificate", "client-vm", "openssl s_client -connect grafana.it.pilot.internal:443 -servername grafana.it.pilot.internal </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer")
            require("grafana.it.pilot.internal" in out and "Certificate Authority" in out,
                    "wrong Grafana certificate identity or issuer")
        self.record("4.5-endpoint", health)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def poll(function, timeout=120):
    deadline = time.monotonic() + timeout
    while True:
        try:
            function()
            return
        except Exception:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)
