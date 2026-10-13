#!/usr/bin/env python3
"""Only fields Pilot actions cannot edit (runbook §3.3 nested-roster exception)."""
import sys
import yaml
from workflow_contract import checkpoint

root = checkpoint()
path = root / ".vault/ipa-identity.yaml"
roster = yaml.safe_load(path.read_text())
if sys.argv[1] == "hosts":
    import json
    hosts = json.loads((root / "facts/topology-inventory.json").read_text())["hosts"]
    roster["hosts"] = [{"name": fqdn, "state": "present", "ip_address": hosts[alias]["ansible_host"]}
                       for alias, fqdn in (("freeipa-server", "ipa1.ipa.pilot.internal"),
                                           ("nexus", "nexus.ipa.pilot.internal"),
                                           ("client-vm", "client-vm.ipa.pilot.internal"))]
elif sys.argv[1] == "onboard":
    # Users/groups/rules were authored through Pilot; never replace them here.
    for user in roster["users"]:
        if user["name"] in ("alice", "bob"):
            user.setdefault("password", {}).update(force_change=True, preserve_existing=True)
    rule = next(r for r in roster["sudo"]["rules"] if r["name"] == "poc-service-admin")
    rule["options"] = ["!authenticate"]
    # hostcat lacks a structured action; the built-in guard specifically
    # requires this admin safety rule before disabling allow_all.
    admin = next(r for r in roster["hbac"]["rules"] if r["name"] == "breakglass-admin-access")
    admin["targets"] = {"hostcat": "all", "hosts": [], "hostgroups": []}
    server = next(s for s in roster["nfs"]["servers"] if s["host"] == "nexus.ipa.pilot.internal")
    server["shares"] = [{"name": "sysops", "state": "present", "source_path": "/srv/nfs/sysops",
        "ownership": {"owner": "root", "group": "data-sysops-rw", "mode": "2770"},
        "acl": {"mode": "authoritative", "access": {"owner": "rwx", "owning_group": "rwx",
            "others": "---", "mask": "rwx", "named_users": [], "named_groups": []},
            "default": {"enabled": True, "owner": "rwx", "owning_group": "rwx",
            "others": "---", "mask": "rwx", "named_users": [], "named_groups": []}},
        "export": {"clients": [{"type": "host", "value": "client-vm.ipa.pilot.internal"}],
                   "options": ["rw", "sync", "root_squash", "sec=krb5i"]},
        "automount": {"enabled": True, "location": "default", "mount_root": "/",
            "map": "auto.sysops", "key": "sysops", "server": "nexus.ipa.pilot.internal",
            "remote_path": "/sysops", "options": ["fstype=nfs4", "sec=krb5i", "hard", "timeo=600", "retrans=2"]}}]
    roster["nfs_clients"] = [{"hostgroup": "nfsclients", "state": "present",
        "automount": {"location": "default", "enable_service": True}, "verification_mounts": ["/sysops"]}]
elif sys.argv[1] == "preserve":
    for user in roster["users"]:
        if user["name"] in ("alice", "bob"):
            user["password"].update(force_change=False, preserve_existing=True)
else:
    raise SystemExit("invalid roster exception operation")
temporary = path.with_suffix(".tmp")
temporary.write_text(yaml.safe_dump(roster, sort_keys=False))
temporary.chmod(0o600)
temporary.replace(path)
