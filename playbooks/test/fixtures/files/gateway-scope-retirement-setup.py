#!/usr/bin/env python3
"""Idempotent scope-bound authorization fixture; never creates test users.

The canonical freeipa-client fixture owns user creation and creation-time keys.
This script uses native IPA typed results captured for the Issue 227 topology.
It retains shared rules and refuses unrelated or broad pre-existing targets.
"""
import json
import sys

from ipalib import api, errors


def sequence(record, name, element_type=str):
    """IPA returns tuples in process; JSON captures use lists.

    Normalize only these supported containers, preserving exact values and
    element types. In particular, numeric 1 and the string 'True' are not an
    enabled boolean flag even though loose equality/truthiness accepts them.
    """
    value = record.get(name, ())
    if type(value) not in (list, tuple) or any(type(item) is not element_type for item in value):
        raise ValueError('fixture IPA attribute has an invalid sequence/type: ' + name)
    return list(value)


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
        if (sequence(rule, 'hostcategory') or sequence(rule, 'usercategory') or sequence(rule, 'servicecategory')
                or sequence(rule, 'memberhost_host') or sequence(rule, 'externalhost')
                or set(sequence(rule, 'memberhost_hostgroup')) - {'pilot-target-i227-owned'}
                or set(sequence(rule, 'memberuser_user')) - {'pilotuser'}
                or sequence(rule, 'memberuser_group')):
            raise ValueError('fixture rule has unrelated/broad authorization: ' + name)
        if kind == 'sudorule' and sequence(rule, 'cmdcategory') != ['all']:
            raise ValueError('fixture sudo rule must have the captured cmdcategory=all contract')
        if 'pilotuser' not in sequence(rule, 'memberuser_user'):
            mutate(kind + '_add_user', name, user=['pilotuser'])
        if 'pilot-target-i227-owned' not in sequence(rule, 'memberhost_hostgroup'):
            mutate(kind + '_add_host', name, hostgroup=['pilot-target-i227-owned'])
        if kind == 'hbacrule':
            if set(sequence(rule, 'memberservice_hbacsvc')) - {'sshd', 'sudo'} or sequence(rule, 'memberservice_hbacsvcgroup'):
                raise ValueError('fixture HBAC rule has unrelated services')
            for service in ('sshd', 'sudo'):
                if service not in sequence(rule, 'memberservice_hbacsvc'):
                    mutate('hbacrule_add_service', name, hbacsvc=[service])
        elif '!authenticate' not in sequence(rule, 'ipasudoopt'):
            mutate('sudorule_add_option', name, ipasudoopt='!authenticate')
        rule = show(kind, name)
        if (sequence(rule, 'memberhost_hostgroup') != ['pilot-target-i227-owned']
                or sequence(rule, 'memberuser_user') != ['pilotuser']):
            raise ValueError('fixture scope/user authorization did not converge')
        if kind == 'hbacrule' and set(sequence(rule, 'memberservice_hbacsvc')) != {'sshd', 'sudo'}:
            raise ValueError('fixture sshd/sudo PAM service authorization did not converge')
        if kind == 'sudorule' and '!authenticate' not in sequence(rule, 'ipasudoopt'):
            raise ValueError('fixture sudo option did not converge')
    allow_all = show('hbacrule', 'allow_all')
    if allow_all is None:
        raise ValueError('fixture requires the native allow_all rule to be observable')
    if sequence(allow_all, 'ipaenabledflag', bool) == [True]:
        mutate('hbacrule_disable', 'allow_all')
    if sequence(show('hbacrule', 'allow_all'), 'ipaenabledflag', bool) != [False]:
        raise ValueError('fixture allow_all disable did not converge')
    print(json.dumps({'changed': changed}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('gateway retirement fixture: ' + str(error), file=sys.stderr)
        sys.exit(1)
