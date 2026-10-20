#!/usr/bin/env python3
"""Generate disposable SIEM mTLS identities outside Git; never a production CA."""

import argparse
import json
import os
import pathlib
import subprocess


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(root.iterdir()):
        raise SystemExit('refusing to overwrite existing PKI')
    ca = root / 'ca'
    for issuer in [ca, root / 'foreign-ca']:
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3',
            '-subj', '/CN=pilot-disposable-relp-test-' + issuer.name,
            '-keyout', str(issuer) + '.key', '-out', str(issuer) + '.pem',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    identities = {}
    (root / 'index').write_text('')
    (root / 'serial').write_text('1000\n')
    config = root / 'ca.cnf'
    config.write_text('[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=' + str(root / 'index') +
                      '\nserial=' + str(root / 'serial') + '\nnew_certs_dir=' + str(root) +
                      '\ncertificate=' + str(ca) + '.pem\nprivate_key=' + str(ca) +
                      '.key\ndefault_md=sha256\npolicy=names\n[names]\ncommonName=supplied\n')
    hosts = ['aq-log', 'aq-ubuntu', 'aq-el', 'unauthorized', 'wrong-server', 'expired',
             'aq-log-rotated', 'aq-ubuntu-rotated', 'aq-el-rotated', 'untrusted-client']
    for host in hosts:
        prefix = root / host
        name = ('aq-ubuntu' if host == 'untrusted-client' else host.removesuffix('-rotated')) + '.test'
        run('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
            '-subj', '/CN=' + name, '-keyout', str(prefix) + '.key', '-out', str(prefix) + '.csr')
        extensions = prefix.with_suffix('.ext')
        extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                              'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:' + name + '\n')
        if host == 'expired':
            run('openssl', 'ca', '-batch', '-notext', '-config', str(config),
                '-startdate', '20000101000000Z', '-enddate', '20000102000000Z',
                '-in', str(prefix) + '.csr', '-extfile', str(extensions), '-out', str(prefix) + '.pem')
        else:
            issuer = root / 'foreign-ca' if host == 'untrusted-client' else ca
            run('openssl', 'x509', '-req', '-in', str(prefix) + '.csr', '-CA', str(issuer) + '.pem',
                '-CAkey', str(issuer) + '.key', '-CAcreateserial', '-days', '2',
                '-extfile', str(extensions), '-out', str(prefix) + '.pem')
        identities[host] = {'cert': prefix.with_suffix('.pem').read_text(),
                            'key': prefix.with_suffix('.key').read_text()}
    values = {'siem_receiver_relp_enabled': True, 'siem_forward_transport': 'relp',
              'siem_relp_port': 20514, 'siem_relp_ca_pem': ca.with_suffix('.pem').read_text(),
              'siem_relp_server_name': 'aq-log.test',
              'siem_relp_client_names': [h + '.test' for h in ['aq-log', 'aq-ubuntu', 'aq-el']],
              'siem_relp_cert_pem': '{{ relp_test_identities[inventory_hostname].cert }}',
              'siem_relp_key_pem': '{{ relp_test_identities[inventory_hostname].key }}',
              'relp_test_identities': identities}
    (root / 'vars.json').write_text(json.dumps(values))
    rotated = dict(values)
    rotated['relp_test_identities'] = dict(identities)
    for host in ['aq-log', 'aq-ubuntu', 'aq-el']:
        rotated['relp_test_identities'][host] = identities[host + '-rotated']
    (root / 'rotated-vars.json').write_text(json.dumps(rotated))
    print('Generated disposable PKI for the aq-log/aq-ubuntu/aq-el topology; private outputs remain outside Git.')


if __name__ == '__main__':
    main()
