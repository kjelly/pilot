"""Read-only users/groups adapter. Desired defaults belong to shared Ansible tasks.

Only allowlisted attributes and key digests cross back to the controller. No
exception message or FreeIPA response is printed on failure.
"""
import base64
import hashlib
import json
import sys


USER_FIELDS = {
    "first": "givenname", "last": "sn", "display_name": "displayname",
    "email": "mail", "uid": "uidnumber", "gid": "gidnumber",
    "login_shell": "loginshell", "home_directory": "homedirectory",
}
GROUP_FIELDS = {"desc": "description", "gid": "gidnumber"}


def hashes(keys):
    # Comments and ordering do not change the SSH key identity.
    result = set()
    for key in keys:
        parts = key.split()
        if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
            raise ValueError("invalid public key")
        blob = base64.b64decode(parts[1], validate=True)
        result.add("SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="))
    return sorted(result)


def strings(value):
    if not isinstance(value, (tuple, list)) or not all(isinstance(v, str) for v in value):
        raise ValueError("invalid string attribute")
    return list(value)


def desired(objects, kind):
    result = []
    for obj in objects:
        fields = USER_FIELDS if kind == "user" else GROUP_FIELDS
        row = {"name": obj["name"], "state": obj["state"], "enabled": obj.get("enabled", False),
               "attributes": {attr: ([] if str(obj[key]) == "" else [str(obj[key])])
                              for key, attr in fields.items() if obj.get(key) is not None},
               "authoritative": obj.get("membership", {}).get("authoritative", True)}
        if kind == "user" and obj.get("ssh_keys") is not None:
            row["key_hashes"] = hashes(obj["ssh_keys"])
        if kind == "group":
            row.update(users=obj.get("membership", {}).get("users", []),
                       groups=obj.get("membership", {}).get("groups", []))
        result.append(row)
    return result


def observed(entries, kind):
    result = []
    fields = USER_FIELDS if kind == "user" else GROUP_FIELDS
    for obj in entries:
        names = strings(obj.get("uid" if kind == "user" else "cn", []))
        if len(names) != 1:
            raise ValueError("invalid primary key")
        row = {"name": names[0], "attributes": {attr: strings(obj.get(attr, [])) for attr in fields.values()}}
        if kind == "user":
            if not isinstance(obj.get("nsaccountlock"), bool):
                raise ValueError("missing account enabled observation")
            row.update(enabled=not obj["nsaccountlock"], key_hashes=hashes(obj.get("ipasshpubkey", [])))
        else:
            # user_find.memberof_group contains indirect membership. Never use it.
            row.update(users=strings(obj.get("member_user", [])), groups=strings(obj.get("member_group", [])))
        result.append(row)
    return result


def complete_find(api, method):
    response = api.Command[method](all=True, sizelimit=0, timelimit=0)
    entries = response.get("result")
    if (response.get("truncated") is not False or not isinstance(entries, (list, tuple))
            or type(response.get("count")) is not int or response["count"] != len(entries)):
        raise ValueError("incomplete search")
    return entries


def snapshot(data, api):
    return {"schema_version": 1,
            "desired_users": desired(data["users"], "user"),
            "desired_groups": desired(data["groups"], "group"),
            "live_users": observed(complete_find(api, "user_find"), "user"),
            "live_groups": observed(complete_find(api, "group_find"), "group")}


def main():
    try:
        from ipalib import api
        data = json.load(sys.stdin)
        api.bootstrap(context="cli", in_server=False)
        api.finalize()
        api.Backend.rpcclient.connect()
        try:
            result = snapshot(data, api)
        finally:
            api.Backend.rpcclient.disconnect()
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print("identity object observation failed; no complete plan is available", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
