"""Read-only users/groups adapter. Desired defaults belong to shared Ansible tasks.

Only allowlisted attributes and key digests cross back to the controller. Nothing
read from FreeIPA, from the roster or from an exception is ever printed: a
failure prints one fixed error class (ERROR_CLASSES) and nothing else, because
the probe runs under no_log and an exception text can quote a value.

Protocol (stdout, one line): the JSON snapshot and exit 0, or
`PILOT_IDENTITY_OBSERVER_ERROR=<class>` and exit 1.
"""
import base64
import hashlib
import json
import sys


ERROR_PREFIX = "PILOT_IDENTITY_OBSERVER_ERROR="
# The vocabulary the probe playbook gates on (freeipa-identity-object-observe.yml)
# and internal/accessgrants/probe_failure.go prints. Adding a class means adding
# its gate and message to both; a test keeps the three lists equal.
ERROR_CLASSES = (
    "bad_input", "ipalib_unavailable", "desired_key_invalid", "kerberos",
    "rpc_failed", "incomplete_search", "account_state_missing", "invalid_response",
)
# Credential fields of apply's normalized users. The probe asks the shared
# normalization not to produce them; seeing one here means the projection broke,
# so refuse instead of handling a secret.
CREDENTIAL_KEYS = ("password", "force_password", "preserve_existing")
USER_FIELDS = {
    "first": "givenname", "last": "sn", "display_name": "displayname",
    "email": "mail", "uid": "uidnumber", "gid": "gidnumber",
    "login_shell": "loginshell", "home_directory": "homedirectory",
}
GROUP_FIELDS = {"desc": "description", "gid": "gidnumber"}


class ObserverError(Exception):
    """Carries only a class from ERROR_CLASSES, never text from the data."""

    def __init__(self, error_class):
        super().__init__(error_class)
        assert error_class in ERROR_CLASSES
        self.error_class = error_class


def load_key_normalizer():
    """Return FreeIPA's own SSH public-key normalizer.

    `ipa user-mod --sshpubkey=K` (what apply runs for every user whose
    ssh_keys is not null) passes K through `normalize_sshpubkey`, which is
    `SSHPublicKey(K).openssh()` (ipalib/util.py, FreeIPA 4.13.4): the normal form
    `[options] keytype base64-blob [comment]` with options sorted and
    re-quoted. FreeIPA then stores the set of normalized strings, and
    `LDAPEntry.generate_modlist` rewrites the attribute whenever that set is not
    exactly the stored one (ipapython/ipaldap.py: values are compared as exact
    strings). So a key that differs only by its comment or its options is a
    modification for apply. Using the same normalizer here is what lets the
    observer report a key difference exactly when apply would mutate; a parser
    of our own would drift from it.
    """
    try:
        from ipapython.ssh import SSHPublicKey
    except Exception:
        raise ObserverError("ipalib_unavailable") from None

    def normalize(text):
        return SSHPublicKey(text).openssh()

    return normalize


def key_digest(canonical):
    """A one-way identity of one normalized key entry; no key material.

    This is a digest of FreeIPA's normalized stored value (options, type,
    blob and comment), not an OpenSSH fingerprint of the blob alone: the comment
    and the options are part of what apply compares. Known limit: user_find
    returns the post-processed value (`convert_sshpubkey_post` normalizes it), so a
    raw LDAP value that a non-FreeIPA tool wrote in another spelling cannot be
    seen here; apply would rewrite it and drift cannot show that.
    """
    return "SHA256:" + base64.b64encode(hashlib.sha256(canonical.encode("utf-8")).digest()).decode().rstrip("=")


def key_digests(keys, normalize, error_class):
    result = set()
    for key in keys:
        try:
            result.add(key_digest(normalize(key)))
        except Exception:
            raise ObserverError(error_class) from None
    return sorted(result)


def manages_keys(obj):
    # Mirrors apply: ssh_keys is reconciled only for active users (state is not
    # absent) whose ssh_keys is not null; [] means "clear every key".
    return obj["state"] != "absent" and obj.get("ssh_keys") is not None


def strings(value):
    if not isinstance(value, (tuple, list)) or not all(isinstance(v, str) for v in value):
        raise ObserverError("invalid_response")
    return list(value)


def default_email_domain(api):
    """FreeIPA's default e-mail domain, or "" when none is set.

    `ipa user-add/user-mod --email=alice` stores `alice@<domain>`: the server
    appends `@ipadefaultemaildomain` to every value without an '@'
    (baseuser.normalize_and_validate_email, FreeIPA 4.13.4). The desired value
    must be compared in that normalized form or a roster `email: alice` is a
    permanent drift that apply never fixes.
    """
    try:
        response = api.Command["config_show"]()
    except Exception as error:
        raise ObserverError(classify_failure(error)) from None
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, dict):
        raise ObserverError("invalid_response")
    value = result.get("ipadefaultemaildomain", [])
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) for v in value):
        raise ObserverError("invalid_response")
    return value[0] if value else ""


def wants_default_domain(obj):
    email = obj.get("email")
    return obj.get("state") != "absent" and email is not None and str(email) != "" and "@" not in str(email)


def normalized_email(email, domain):
    return email + "@" + domain if "@" not in email and domain else email


def desired(objects, kind, normalize=None, domain=""):
    result = []
    for obj in objects:
        if not isinstance(obj, dict) or not isinstance(obj.get("name"), str) or not isinstance(obj.get("state"), str):
            raise ObserverError("bad_input")
        if kind == "user" and any(key in obj for key in CREDENTIAL_KEYS):
            raise ObserverError("bad_input")
        membership = obj.get("membership", {})
        if not isinstance(membership, dict):
            raise ObserverError("bad_input")
        fields = USER_FIELDS if kind == "user" else GROUP_FIELDS
        row = {"name": obj["name"], "state": obj["state"], "enabled": obj.get("enabled", False),
               "attributes": {attr: ([] if str(obj[key]) == "" else [str(obj[key])])
                              for key, attr in fields.items() if obj.get(key) is not None},
               "authoritative": membership.get("authoritative", True)}
        if kind == "user" and row["attributes"].get("mail"):
            row["attributes"]["mail"] = [normalized_email(row["attributes"]["mail"][0], domain)]
        if kind == "user" and manages_keys(obj):
            if not isinstance(obj["ssh_keys"], list) or not all(isinstance(k, str) for k in obj["ssh_keys"]):
                raise ObserverError("bad_input")
            row["key_hashes"] = key_digests(obj["ssh_keys"], normalize, "desired_key_invalid")
        if kind == "group":
            row.update(users=membership.get("users", []), groups=membership.get("groups", []))
        result.append(row)
    return result


def observed(entries, kind, key_users=frozenset(), normalize=None):
    """key_users: lowercase names whose desired row manages SSH keys.

    Keys of every other user are never parsed: a realm may hold keys that FreeIPA
    accepts and this adapter has no business with (an unmanaged user's key must
    not fail the whole observation).
    """
    result = []
    fields = USER_FIELDS if kind == "user" else GROUP_FIELDS
    for obj in entries:
        names = strings(obj.get("uid" if kind == "user" else "cn", []))
        if len(names) != 1:
            raise ObserverError("invalid_response")
        row = {"name": names[0], "attributes": {attr: strings(obj.get(attr, [])) for attr in fields.values()}}
        if kind == "user":
            if not isinstance(obj.get("nsaccountlock"), bool):
                raise ObserverError("account_state_missing")
            row["enabled"] = not obj["nsaccountlock"]
            if names[0].lower() in key_users:
                row["key_hashes"] = key_digests(strings(obj.get("ipasshpubkey", [])), normalize, "invalid_response")
        else:
            # user_find.memberof_group contains indirect membership. Never use it.
            row.update(users=strings(obj.get("member_user", [])), groups=strings(obj.get("member_group", [])))
        result.append(row)
    return result


def classify_failure(error):
    """A fixed class for an exception raised by the FreeIPA client library."""
    names = {cls.__name__ for cls in type(error).__mro__}
    if names & {"AuthenticationError", "KerberosError", "CCacheError", "NoCCacheError", "TicketExpired"}:
        return "kerberos"
    return "rpc_failed"


def complete_find(api, method, **options):
    """One search with no size or time limit that must report itself complete."""
    options = options or {"all": True}
    try:
        response = api.Command[method](sizelimit=0, timelimit=0, **options)
    except Exception as error:
        raise ObserverError(classify_failure(error)) from None
    if not isinstance(response, dict):
        raise ObserverError("invalid_response")
    entries = response.get("result")
    if (response.get("truncated") is not False or not isinstance(entries, (list, tuple))
            or type(response.get("count")) is not int or response["count"] != len(entries)):
        raise ObserverError("incomplete_search")
    return entries


def preserved_names(entries):
    """Names of preserved users: deleted with --preserve, hidden from user_find.

    A plain user_find never returns them, yet apply meets them: `user-del` on a
    roster `state: absent` user deletes the preserved account for good, and a
    `present` roster user that is preserved cannot be created again nor added to
    a group. Only the names are needed.
    """
    names = []
    for obj in entries:
        found = strings(obj.get("uid", []))
        if len(found) != 1:
            raise ObserverError("invalid_response")
        names.append(found[0])
    return names


def snapshot(data, api):
    users, groups = data["users"], data["groups"]
    key_users = {u["name"].lower() for u in users
                 if isinstance(u, dict) and isinstance(u.get("name"), str)
                 and isinstance(u.get("state"), str) and manages_keys(u)}
    normalize = load_key_normalizer() if key_users else None
    # Asked only when a desired e-mail needs it: most realms never call it.
    domain = default_email_domain(api) if any(
        isinstance(u, dict) and wants_default_domain(u) for u in users) else ""
    return {"schema_version": 1,
            "desired_users": desired(users, "user", normalize, domain),
            "desired_groups": desired(groups, "group"),
            "live_users": observed(complete_find(api, "user_find"), "user", key_users, normalize),
            "preserved_users": preserved_names(complete_find(api, "user_find", preserved=True, pkey_only=True)),
            "live_groups": observed(complete_find(api, "group_find"), "group")}


def read_input(stream):
    try:
        data = json.load(stream)
    except Exception:
        raise ObserverError("bad_input") from None
    if (not isinstance(data, dict) or not isinstance(data.get("users"), list)
            or not isinstance(data.get("groups"), list)):
        raise ObserverError("bad_input")
    return data


def connect():
    try:
        from ipalib import api
    except Exception:
        raise ObserverError("ipalib_unavailable") from None
    try:
        api.bootstrap(context="cli", in_server=False)
        api.finalize()
        api.Backend.rpcclient.connect()
    except Exception as error:
        raise ObserverError(classify_failure(error)) from None
    return api


def main():
    api = None
    try:
        data = read_input(sys.stdin)
        api = connect()
        result = snapshot(data, api)
    except ObserverError as error:
        print(ERROR_PREFIX + error.error_class)
        return 1
    except Exception:
        # A malformed reply that no check above names. The text is never shown.
        print(ERROR_PREFIX + "invalid_response")
        return 1
    finally:
        if api is not None:
            try:
                api.Backend.rpcclient.disconnect()
            except Exception:
                pass
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
