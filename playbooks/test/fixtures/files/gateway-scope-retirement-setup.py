#!/usr/bin/env python3
"""Idempotent scope-bound authorization fixture; never creates test users.

The canonical freeipa-client fixture owns user creation and creation-time keys.
This script uses native IPA typed results captured for the Issue 227 topology.
It retains shared rules and refuses unrelated or broad pre-existing targets.
"""
import json
import sys

from ipalib import api, errors


def main():
    api.bootstrap(context='cli')
    api.finalize()
    api.Backend.rpcclient.connect()
    changed = False

    def show(kind, name):
        try:
            return api.Command[kind + '_show'](name, all=True)['result']
        except errors.NotFound:
            return None

    def mutate(command, name, **options):
        nonlocal changed
        result = api.Command[command](name, **options)

        def failures(value):
            if isinstance(value, dict):
                return any(failures(item) for item in value.values())
            return bool(value)

        if failures(result.get('failed', {})):
            raise ValueError('fixture IPA membership mutation failed: ' + command)
        changed = True

    for kind, name in [('hbacrule', 'i227-owned-hbac'), ('sudorule', 'i227-owned-sudo')]:
        rule = show(kind, name)
        if rule is None:
            mutate(kind + '_add', name, **({'cmdcategory': 'all'} if kind == 'sudorule' else {}))
            rule = show(kind, name)
        if (rule.get('hostcategory') or rule.get('usercategory') or rule.get('servicecategory')
                or rule.get('memberhost_host') or rule.get('externalhost')
                or set(rule.get('memberhost_hostgroup', [])) - {'pilot-target-i227-owned'}
                or set(rule.get('memberuser_user', [])) - {'pilotuser'}
                or rule.get('memberuser_group')):
            raise ValueError('fixture rule has unrelated/broad authorization: ' + name)
        if kind == 'sudorule' and rule.get('cmdcategory') != ['all']:
            raise ValueError('fixture sudo rule must have the captured cmdcategory=all contract')
        if 'pilotuser' not in rule.get('memberuser_user', []):
            mutate(kind + '_add_user', name, user=['pilotuser'])
        if 'pilot-target-i227-owned' not in rule.get('memberhost_hostgroup', []):
            mutate(kind + '_add_host', name, hostgroup=['pilot-target-i227-owned'])
        if kind == 'hbacrule':
            if set(rule.get('memberservice_hbacsvc', [])) - {'sshd', 'sudo'} or rule.get('memberservice_hbacsvcgroup'):
                raise ValueError('fixture HBAC rule has unrelated services')
            for service in ('sshd', 'sudo'):
                if service not in rule.get('memberservice_hbacsvc', []):
                    mutate('hbacrule_add_service', name, hbacsvc=[service])
        elif '!authenticate' not in rule.get('ipasudoopt', []):
            mutate('sudorule_add_option', name, ipasudoopt='!authenticate')
        rule = show(kind, name)
        if (rule.get('memberhost_hostgroup') != ['pilot-target-i227-owned']
                or rule.get('memberuser_user') != ['pilotuser']):
            raise ValueError('fixture scope/user authorization did not converge')
        if kind == 'hbacrule' and set(rule.get('memberservice_hbacsvc', [])) != {'sshd', 'sudo'}:
            raise ValueError('fixture sshd/sudo PAM service authorization did not converge')
        if kind == 'sudorule' and '!authenticate' not in rule.get('ipasudoopt', []):
            raise ValueError('fixture sudo option did not converge')
    allow_all = show('hbacrule', 'allow_all')
    if allow_all is None:
        raise ValueError('fixture requires the native allow_all rule to be observable')
    if allow_all.get('ipaenabledflag') == [True]:
        mutate('hbacrule_disable', 'allow_all')
    if show('hbacrule', 'allow_all').get('ipaenabledflag') != [False]:
        raise ValueError('fixture allow_all disable did not converge')
    print(json.dumps({'changed': changed}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('gateway retirement fixture: ' + str(error), file=sys.stderr)
        sys.exit(1)
