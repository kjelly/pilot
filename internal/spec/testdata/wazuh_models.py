"""Native-command models shared by the Wazuh Python harnesses (no daemon, no host state)."""
import subprocess


class Docker:
    """Native docker and Wazuh-manager command model for the central stack (no daemon).

    w is the coordinator module under test: the model raises ITS Refused, so the
    code under test sees the same exception class a real native failure produces.
    """
    def __init__(self, w, root, release='4.14.1', agents=None):
        self.w = w
        self.release = release
        self.managed = root / 'managed'
        self.project = self.managed / ('wazuh-docker-' + release) / 'single-node'
        self.project.mkdir(parents=True)
        self.compose = self.project / 'docker-compose.yml'
        self.compose.write_text('services: {}\n')
        self.agents = {'001': release} if agents is None else agents
        self.running = True
        self.stopped_daemons = set()
        self.tags = {service: release for service in w.SERVICES}
        self.repo_digests = True
        self.drop = set()
        self.indexer_status = 'green'
        self.calls = []
        self.containers = []
        for number, service in enumerate(w.SERVICES):
            self.containers.append({'Id': 'container-' + str(number), 'Image': 'sha256:' + str(number + 1) * 64,
                                    'State': {'Running': True}, 'Mounts': [], 'service': service})

    def inspect(self):
        rows = []
        for row in self.containers:
            if row['service'] in self.drop:
                continue
            repo = 'wazuh/' + row['service'].replace('.', '-')
            rows.append({'Id': row['Id'], 'Image': row['Image'], 'State': {'Running': self.running and row['State']['Running']},
                         'Config': {'Image': repo + ':' + self.tags[row['service']],
                                    'Labels': {'com.docker.compose.project': 'single-node',
                                               'com.docker.compose.service': row['service'],
                                               'com.docker.compose.project.working_dir': str(self.project),
                                               'com.docker.compose.project.config_files': str(self.compose)}}})
        return rows

    def run(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        self.calls.append(argv)
        rc, text = 0, ''
        if argv[:2] == ['docker', 'info']:
            pass
        elif argv[:2] == ['docker', 'ps']:
            text = '\n'.join(row['Id'] for row in self.inspect())
        elif argv[-1] == 'info' and 'wazuh-control' in argv[-2]:
            text = 'WAZUH_VERSION="v' + self.release + '"\nWAZUH_REVISION="40100"\nWAZUH_TYPE="server"\n'
        elif argv[-1] == 'status':
            required = ('modulesd', 'logcollector', 'remoted', 'analysisd', 'execd', 'db', 'authd', 'apid')
            text = '\n'.join('wazuh-' + name + (' not running...' if name in self.stopped_daemons else ' is running...') for name in required)
            text += '\nwazuh-clusterd not running...\n'
            rc = 1
        elif '-l' in argv:
            # Shape captured from the real chain run recorded in docs/runbooks/wazuh-fim.md (agent_control -l).
            text = ('Wazuh agent_control. List of available agents:\n'
                    '   ID: 000, Name: wazuh-manager (server), IP: 127.0.0.1, Active/Local\n'
                    + ''.join('   ID: %s, Name: agent-%s, IP: any, Active\n' % (key, key) for key in self.agents) + '\n')
        elif '-i' in argv:
            # The -i block is modeled on the documented field layout; only the lines the parser reads matter.
            identifier = argv[argv.index('-i') + 1]
            release = self.agents[identifier]
            text = ('Wazuh agent_control. Agent information:\n   Agent ID:   %s\n   Agent Name: agent-%s\n   IP address: any\n'
                    '   Status:     Active\n\n   Client version:      %s\n' % (identifier, identifier,
                                                                            'unknown' if release == 'unknown' else 'Wazuh v' + release))
        else:
            raise AssertionError(argv)
        if rc not in kwargs.get('allowed', (0,)):
            raise self.w.Refused('injected native probe failure')
        return subprocess.CompletedProcess(argv, rc, text, '')

    def json(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        self.calls.append(argv)
        if argv[:2] == ['docker', 'inspect']:
            return [row for row in self.inspect() if row['Id'] in argv[2:]]
        if argv[:3] == ['docker', 'image', 'inspect']:
            identifier = argv[-1]
            service = next(row['service'] for row in self.containers if row['Image'] == identifier)
            repo = 'wazuh/' + service.replace('.', '-')
            digests = {True: [repo + '@' + identifier], False: [],
                       'foreign': ['attacker/' + repo.split('/')[1] + '@' + identifier],
                       'malformed': [repo + '@sha256:not-a-digest', repo + ':4.14.1']}[self.repo_digests]
            return [{'Id': identifier, 'RepoDigests': digests}]
        if 'curl' in argv:
            return {'status': self.indexer_status}
        if argv[-1] in ('/usr/share/wazuh-dashboard/plugins/wazuh/package.json', '/usr/share/wazuh-indexer/VERSION.json'):
            return {'version': self.release}
        raise AssertionError(argv)
