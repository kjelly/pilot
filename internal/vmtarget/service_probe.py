#!/usr/bin/env python3
"""Bounded native cache GET; no management credentials or repair operations."""
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

probe = json.loads(sys.argv[1])
origin = urllib.parse.urlsplit(probe['endpoint'])
resource = probe['resource']
url = resource if probe['capability'] == 'apt' else urllib.parse.urlunsplit((origin.scheme, origin.netloc, resource, '', ''))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

handlers = [NoRedirect(), urllib.request.ProxyHandler({'http': probe['endpoint'], 'https': probe['endpoint']} if probe['capability'] == 'apt' else {})]
opener = urllib.request.build_opener(*handlers)
accept = 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/json, */*'

def read(target, token=None):
    headers = {'Accept': accept}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    response = opener.open(urllib.request.Request(target, headers=headers), timeout=2)
    with response:
        if response.status != 200:
            raise ValueError('non-success data read')
        body = response.read(8 * 1024 * 1024 + 1)
        if len(body) > 8 * 1024 * 1024:
            raise ValueError('oversized response')
        return body

try:
    try:
        body = read(url)
    except urllib.error.HTTPError as error:
        if probe['capability'] != 'oci' or error.code != 401:
            raise
        challenge = error.headers.get('WWW-Authenticate', '')
        if not challenge.startswith('Bearer '):
            raise ValueError('unsupported registry challenge')
        pairs = re.findall(r'([a-z]+)="([^"\r\n]*)"', challenge[7:])
        params = dict(pairs)
        if len(params) != len(pairs):
            raise ValueError('ambiguous registry challenge')
        realm = urllib.parse.urlsplit(params.get('realm', ''))
        repository = re.split(r'/(?:manifests|blobs)/', resource[4:], maxsplit=1)[0]
        if realm.scheme != origin.scheme or realm.port != origin.port or realm.hostname not in (origin.hostname, probe.get('bind_ip')) or realm.path != '/service/token' or realm.query or realm.fragment or realm.username:
            raise ValueError('unsafe registry token realm')
        if params.get('scope') != 'repository:' + repository + ':pull' or not params.get('service'):
            raise ValueError('unsafe registry token scope')
        token_url = urllib.parse.urlunsplit((realm.scheme, realm.netloc, realm.path, urllib.parse.urlencode({'scope': params['scope'], 'service': params['service']}), ''))
        payload = json.loads(read(token_url))
        token = payload.get('token') or payload.get('access_token')
        if not isinstance(token, str) or not token or len(token) > 65536 or '\r' in token or '\n' in token:
            raise ValueError('invalid registry token')
        body = read(url, token)
    if probe.get('sha256') and hashlib.sha256(body).hexdigest() != probe['sha256']:
        raise ValueError('content digest mismatch')
    if probe.get('contains') and probe['contains'].encode() not in body:
        raise ValueError('content marker mismatch')
except Exception:
    # Do not disclose request bodies, bearer tokens or private endpoints.
    print('required cache data probe failed', file=sys.stderr)
    sys.exit(1)
