#!/usr/bin/env python3
"""Wazuh-only endpoint binding; raw/TLS names never become identity proof."""
import ipaddress
import json
import socket
import sys


def numeric(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def address(value):
    direct = numeric(value)
    if direct:
        return direct
    values = {str(ipaddress.ip_address(row[4][0])) for row in
              socket.getaddrinfo(value, None, socket.AF_INET, socket.SOCK_STREAM)}
    if len(values) != 1:
        raise ValueError('endpoint does not resolve to one numeric transport')
    return values.pop()


def select(request):
    raw = request['raw']
    records = request['records']
    matches = [item for item in records if raw in
               (item['name'], item['address'], item.get('fqdn', ''))]
    if len(matches) > 1:
        raise ValueError('ambiguous inventory endpoint association')
    if request.get('manager') and not matches and numeric(raw) is None:
        raise ValueError('manager endpoint has no trusted inventory association')
    return {'transport': matches[0]['address'] if matches else raw,
            'association': matches[0]['name'] if matches else None}


def bind(request):
    result = address(request['resolved'])
    selected = select(request)
    expected = request.get('manager')
    if expected:
        records = request['records']
        connections = [(item['name'], address(item['address'])) for item in records]
        matches = [name for name, value in connections if value == result]
        if matches != [expected] or selected['association'] not in (None, expected):
            raise ValueError('manager endpoint differs from unique delegated inventory identity')
    return {'address': result, 'association': selected['association']}


if __name__ == '__main__':
    try:
        request = json.loads(sys.argv[2])
        result = {'select': select, 'bind': bind}[sys.argv[1]](request)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, KeyError, OSError, TypeError):
        print(json.dumps({'error': 'Wazuh endpoint identity is unknown, ambiguous or different'}))
        sys.exit(2)
