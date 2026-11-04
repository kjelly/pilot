#!/usr/bin/env python3
"""Server-authoritative gateway scope ownership and retirement barrier.

The lock covers live IPA probes, mutations and durable journal publication.
Names and descriptions never establish ownership. A legacy group requires an
operator-supplied exact ipauniqueid adoption; recreation invalidates ownership.
"""
import contextlib
import fcntl
import json
import ipaddress
import os
import re
import socket
import stat
import sys
import tempfile


def fqdn(value):
    if not isinstance(value, str):
        raise ValueError('an explicit canonical FQDN is required')
    value = value.strip().lower().removesuffix('.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('a host identity cannot be a transport IP address')
    if (len(value) > 253 or '.' not in value
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                   for label in value.split('.'))):
        raise ValueError('an explicit canonical FQDN is required')
    return value


class Store:
    def __init__(self, path, domain, authority, readonly):
        self.path, self.domain, self.authority, self.readonly = path, domain, authority, readonly

    @contextlib.contextmanager
    def locked(self):
        parent = os.path.dirname(self.path)
        if not os.path.exists(parent):
            if self.readonly:
                yield self.empty()
                return
            os.mkdir(parent, 0o700)
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if st.st_uid != os.geteuid() or st.st_mode & 0o022:
                raise ValueError('unsafe gateway lifecycle directory ownership/permissions')
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                source = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
            except FileNotFoundError:
                state = self.empty()
            else:
                with os.fdopen(source) as stream:
                    st = os.fstat(stream.fileno())
                    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1 or st.st_mode & 0o077:
                        raise ValueError('unsafe gateway lifecycle ledger')
                    state = json.load(stream)
            if (state.get('version') != 1 or state.get('domain') != self.domain
                    or state.get('authority') != self.authority
                    or not isinstance(state.get('scopes'), dict)
                    or not isinstance(state.get('retired'), dict)):
                raise ValueError('gateway lifecycle ledger identity/schema mismatch')
            yield state
        finally:
            os.close(fd)

    def empty(self):
        return dict(version=1, domain=self.domain, authority=self.authority, scopes={}, retired={})

    def save(self, state):
        if self.readonly:
            raise ValueError('read-only lifecycle operation attempted a write')
        parent = os.path.dirname(self.path)
        fd, temporary = tempfile.mkstemp(prefix='.gateway-scopes-', dir=parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(state, stream, sort_keys=True)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class Lifecycle:
    def __init__(self, api, not_found, store, rule_id):
        self.api, self.not_found, self.store, self.rule_id = api, not_found, store, rule_id
        self.changed = False

    def show(self, kind, name, **options):
        try:
            result = self.api[kind + '_show'](name, all=True, **options)['result']
            result = {key.lower(): value for key, value in result.items()}
            identity = result.get('fqdn' if kind == 'host' else 'cn', [])
            if len(identity) != 1 or identity[0].lower().rstrip('.') != name.lower().rstrip('.'):
                raise ValueError('IPA probe returned a different or missing resource identity')
            return result
        except self.not_found:
            return None

    def group_id(self, group):
        values = {key.lower(): value for key, value in group.items()}.get('ipauniqueid', [])
        if len(values) != 1 or not re.fullmatch(r'[0-9a-fA-F-]{36}', values[0]):
            raise ValueError('live hostgroup immutable ID unavailable')
        return values[0].lower()

    def resolve_host_identities(self, requested, retired):
        """Keep show() strict; this is the native legacy-short compatibility boundary.

        Explicit/mapped canonical retirements are filtered before lookup, even
        after their host object was deleted. Short names need a live native
        resolution; no suffix or retired-basename guessing grants an identity.
        """
        resolved, blocked = set(), set()
        guidance = '; use the exact canonical FQDN or inventory ipa_client_fqdn mapping'
        for raw in requested:
            if not isinstance(raw, str):
                raise ValueError('invalid gateway host identity' + guidance)
            host = raw.strip().lower()
            if '.' in host:
                canonical = fqdn(host)
                if canonical in retired:
                    blocked.add(canonical)
                    continue
                if self.show('host', canonical) is None:
                    raise ValueError('gateway host not found: ' + canonical + guidance)
            else:
                if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', host):
                    raise ValueError('invalid legacy short host identity: ' + host + guidance)
                try:
                    response = self.api['host_show'](host, all=True)
                except self.not_found:
                    raise ValueError('legacy short host is missing or ambiguous: ' + host + guidance) from None
                except Exception as error:
                    raise ValueError('native legacy short lookup failed for ' + host + ': ' + str(error) + guidance) from error
                result = response.get('result') if isinstance(response, dict) else None
                names = result.get('fqdn') if isinstance(result, dict) else None
                if (type(names) not in (list, tuple) or len(names) != 1
                        or type(names[0]) is not str):
                    raise ValueError('native short-host lookup has no unique canonical FQDN: ' + host + guidance)
                try:
                    canonical = fqdn(names[0])
                except ValueError as error:
                    raise ValueError('invalid native identity for short ' + host + ': ' + str(error) + guidance) from error
                if canonical.split('.', 1)[0] != host:
                    raise ValueError('native short-host lookup returned a different resource: ' + host + guidance)
            if canonical in retired:
                blocked.add(canonical)
            else:
                resolved.add(canonical)
        return sorted(resolved), sorted(blocked)

    def owned(self, state, name, group):
        entry = state['scopes'].get(name)
        return (entry is not None and entry.get('group') == name
                and entry.get('scope') and 'pilot-target-' + entry['scope'] == name
                and entry.get('id') == self.group_id(group))

    def mutate(self, command, name, **options):
        result = self.api[command](name, **options)
        if result.get('failed'):
            # IPA membership APIs return nested empty containers on success.
            def failures(value):
                if isinstance(value, dict):
                    return any(failures(v) for v in value.values())
                return bool(value)
            if failures(result['failed']):
                raise ValueError('IPA rejected ' + command + '; retry after resolving live state')
        self.changed = True
        return result

    def auto_rule(self, state, name, adopt_id='', readonly=False):
        rule = self.show('automember', name, type='hostgroup', raw=True)
        if rule is None:
            return None
        group = self.show('hostgroup', name, raw=True)
        target = rule.get('automembertargetgroup', [])
        if group is None or len(target) != 1 or str(target[0]).lower() != str(group.get('dn', '')).lower():
            raise ValueError('automember target differs from the exact owned hostgroup')
        entry = state['scopes'][name]
        identity = self.rule_id(str(rule['dn']))
        if entry.get('automember_id') == identity:
            return rule
        if not adopt_id or adopt_id.lower() != identity:
            raise ValueError('unproven automember ownership for ' + name +
                             '; inspect its LDAP entryUUID and supply gateway_scope_adopt_automember_id/--adopt-automember-id with the exact group adoption ID')
        if readonly:
            return rule
        entry['automember_id'] = identity
        self.store.save(state)
        self.changed = True
        return self.auto_rule(state, name)

    def exclude(self, state, name, host):
        rule = self.auto_rule(state, name)
        if rule is None:
            return
        condition = 'fqdn=^' + re.escape(host) + '$'
        if condition not in rule.get('automemberexclusiveregex', []):
            self.mutate('automember_add_condition', name, type='hostgroup', key='fqdn',
                        automemberexclusiveregex=['^' + re.escape(host) + '$'])
        rule = self.show('automember', name, type='hostgroup', raw=True)
        if rule is None or condition not in rule.get('automemberexclusiveregex', []):
            raise ValueError('retirement automember exclusion did not converge')

    def classify(self, state, hosts, managed):
        result = {}
        for host in hosts:
            obj = self.show('host', host)
            groups = [] if obj is None else obj.get('memberof_hostgroup', [])
            result[host] = []
            for name in groups:
                name = name.lower()
                group = self.show('hostgroup', name, raw=True)
                if group is None:
                    raise ValueError('membership changed while probing; retry')
                if self.owned(state, name, group):
                    result[host].append(name)
                elif name not in managed:
                    raise ValueError('unproven hostgroup ownership: ' + name +
                                     '; reconcile its owning roster/controller or explicitly adopt the live gateway group exact ipauniqueid before retrying')
        return result

    def retire(self, state, data, readonly):
        authorized = {fqdn(item['fqdn']) for item in data['retirements']}
        absent = {fqdn(host) for host in data.get('absent_hosts', [])}
        hosts = sorted(authorized | absent)
        if not readonly and absent - authorized:
            raise ValueError('gateway mutation requires an exact authorized retirement mapping for every host')
        managed = {name.lower() for name in data.get('managed_hostgroups', [])}
        classified = self.classify(state, hosts, managed)
        # Retirement must also cover scopes where this host is not currently
        # a member. Otherwise an automember rebuild can add it after detach.
        scopes, auto_rules = [], []
        for name in state['scopes']:
            group = self.show('hostgroup', name, raw=True)
            if group is None:
                continue
            if not self.owned(state, name, group):
                raise ValueError('gateway scope immutable ID changed: ' + name)
            rule = self.auto_rule(state, name)
            if rule is not None:
                auto_rules.append(rule)
            scopes.append(name)
        if data.get('require_mappings'):
            for host in sorted(absent - authorized):
                condition = 'fqdn=^' + re.escape(host) + '$'
                auto_pending = any(rule.get('automemberinclusiveregex')
                                   and condition not in rule.get('automemberexclusiveregex', [])
                                   for rule in auto_rules)
                if (classified[host] or auto_pending
                        or state['retired'].get(host, {}).get('status') == 'pending'):
                    raise ValueError('gateway retirement for ' + host +
                                     ' requires an exact authorized alias/FQDN/stage mapping; restore the intended inventory ipa_client_fqdn or supply ipa_identity_ssh_cache_retirements with alias, fqdn, stage, reason and origin before retrying')
        if readonly:
            return dict(ready=True, hosts=hosts, owned=classified, changed=False)
        for item in data['retirements']:
            if not item.get('reason') or not item.get('origin') or not item.get('stage'):
                raise ValueError('retirement requires authorized stage, reason and origin')
        # Persist all barriers before the first IPA mutation. They survive
        # partial failure and keep later publication from re-adding the host.
        for host in hosts:
            if host not in state['retired']:
                state['retired'][host] = dict(status='pending', authorization=[i for i in data['retirements'] if fqdn(i['fqdn']) == host])
                self.changed = True
        self.store.save(state)
        for name in scopes:
            for host in hosts:
                self.exclude(state, name, host)
        for host, names in classified.items():
            for name in names:
                self.mutate('hostgroup_remove_member', name, host=[host])
            remaining = self.classify(state, [host], managed)[host]
            if remaining:
                raise ValueError('gateway membership removal did not converge')
            if state['retired'][host]['status'] != 'detached':
                state['retired'][host]['status'] = 'detached'
                self.changed = True
            self.store.save(state)
        return dict(ready=True, hosts=hosts, changed=self.changed)

    def publish(self, state, data, readonly):
        scope = data['scope']
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', scope):
            raise ValueError('invalid gateway scope')
        name, action = 'pilot-target-' + scope, data.get('automember', 'none')
        if action not in ('none', 'enable', 'disable'):
            raise ValueError('invalid automember action')
        desired, blocked = self.resolve_host_identities(data.get('hosts', []), state['retired'])
        group = self.show('hostgroup', name, raw=True)
        adopt = data.get('adopt_id', '').lower()
        if group is not None and not self.owned(state, name, group):
            if not adopt or adopt != self.group_id(group):
                raise ValueError('unproven gateway group ' + name + '; inspect its live ipauniqueid and explicitly adopt that exact ID with gateway_scope_adopt_id/--adopt-group-id')
        if group is None and name in state['scopes']:
            raise ValueError('owned gateway group disappeared; restore it or explicitly resolve ownership ledger before retrying')
        # Same-named automember rules also need immutable ownership proof.
        # Operational LDAP entryUUID is read locally through SASL EXTERNAL;
        # the ordinary IPA API does not expose this operational attribute.
        adopt_auto = data.get('adopt_automember_id', '') if adopt and group is not None and adopt == self.group_id(group) else ''
        if group is not None:
            preview = dict(state, scopes=dict(state['scopes']))
            if not self.owned(state, name, group):
                preview['scopes'][name] = dict(group=name, scope=scope, id=self.group_id(group))
            self.auto_rule(preview, name, adopt_id=adopt_auto, readonly=True)
        elif self.show('automember', name, type='hostgroup', raw=True) is not None:
            raise ValueError('unproven dangling automember rule blocks gateway group creation')
        current = [] if group is None else [fqdn(host) for host in self.show('hostgroup', name).get('member_host', [])]
        plan = dict(add=sorted(set(desired) - set(current)), remove=sorted(set(current) - set(desired)),
                    keep=sorted(set(desired) & set(current)), blocked=blocked)
        if readonly:
            return dict(plan, changed=False)
        if group is None:
            if action == 'disable':
                return dict(changed=False)
            group = self.mutate('hostgroup_add', name, description='Pilot Access Gateway target scope: ' + scope, all=True, raw=True)['result']
        if not self.owned(state, name, group):
            state['scopes'][name] = dict(group=name, scope=scope, id=self.group_id(group))
            self.store.save(state)
            self.changed = True
        rule = self.auto_rule(state, name, adopt_id=adopt_auto)
        if action == 'enable' and rule is None:
            self.mutate('automember_add', name, type='hostgroup')
            rule = self.show('automember', name, type='hostgroup', raw=True)
            state['scopes'][name]['automember_id'] = self.rule_id(str(rule['dn']))
            self.store.save(state)
        # Every pending AND completed retirement is applied to any rule before
        # enabling its inclusive condition or changing membership.
        for host in sorted(state['retired']):
            self.exclude(state, name, host)
        if action != 'disable':
            for host in plan['remove']:
                self.mutate('hostgroup_remove_member', name, host=[host])
            for host in plan['add']:
                self.mutate('hostgroup_add_member', name, host=[host])
            observed = self.show('hostgroup', name)
            if observed is None or sorted(observed.get('member_host', [])) != desired:
                raise ValueError('gateway scope membership did not converge')
        if action == 'enable':
            rule = self.show('automember', name, type='hostgroup', raw=True)
            if 'fqdn=.*' not in rule.get('automemberinclusiveregex', []):
                self.mutate('automember_add_condition', name, type='hostgroup', key='fqdn', automemberinclusiveregex=['.*'])
        elif action == 'disable' and self.show('automember', name, type='hostgroup', raw=True) is not None:
            self.mutate('automember_del', name, type='hostgroup')
            state['scopes'][name].pop('automember_id', None)
            self.store.save(state)
        return dict(plan, changed=self.changed)


def main():
    operation, path = sys.argv[1:]
    data = json.load(sys.stdin)
    authority = fqdn(data['authority'])
    if os.geteuid() != 0 or fqdn(socket.getfqdn()) != authority:
        raise ValueError('gateway lifecycle must run as root on its designated FreeIPA authority ' + authority)
    readonly = operation == 'inspect' or bool(data.get('readonly'))
    from ipalib import api, errors
    api.bootstrap(context='cli', server=authority, xmlrpc_uri='https://' + authority + '/ipa/xml')
    api.finalize()
    domain = fqdn(data.get('domain') or api.env.domain)
    if api.env.domain.lower() != domain:
        raise ValueError('configured FreeIPA domain differs from authorized domain')
    api.Backend.rpcclient.connect()
    import ldap
    import ldap.sasl
    from urllib.parse import quote
    socket_path = '/run/slapd-' + api.env.realm.replace('.', '-') + '.socket'
    directory = ldap.initialize('ldapi://' + quote(socket_path, safe=''))
    directory.sasl_interactive_bind_s('', ldap.sasl.external())

    def rule_id(dn):
        entries = directory.search_s(dn, ldap.SCOPE_BASE, '(objectClass=*)', ['entryUUID'])
        if len(entries) != 1 or len(entries[0][1].get('entryUUID', [])) != 1:
            raise ValueError('automember immutable LDAP entryUUID unavailable')
        value = entries[0][1]['entryUUID'][0].decode('ascii').lower()
        if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value):
            raise ValueError('invalid automember LDAP entryUUID')
        return value

    store = Store(path, domain, authority, readonly)
    with store.locked() as state:
        lifecycle = Lifecycle(api.Command, errors.NotFound, store, rule_id)
        if operation in ('inspect', 'retire'):
            result = lifecycle.retire(state, data, readonly)
        elif operation == 'publish':
            result = lifecycle.publish(state, data, readonly)
        else:
            raise ValueError('unknown gateway lifecycle operation')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('gateway scope lifecycle: ' + str(error), file=sys.stderr)
        sys.exit(1)
