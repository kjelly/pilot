"""Native-command models shared by the Wazuh Python harnesses (no daemon, no host state).

Wherever the Issue #244 part-A target run (2026-11-05, Ubuntu 24.04 / AlmaLinux 9 VMs, Wazuh
4.14.1 and 4.14.9) saved a real capture, the model answers from that capture verbatim
(native-captures/, one file per command and outcome, the return code in the file name) and only
substitutes the fields a test varies (ids, names, releases, one daemon's state). What is not in
native-captures/ is MODELED and says so where it is produced.
"""
import json
from pathlib import Path
import re
import subprocess

CAPTURES = Path(__file__).resolve().parent / 'native-captures'


def capture(name):
    return (CAPTURES / name).read_text()


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
        # `docker info --format {{.DockerRootDir}}`: a real private directory, as on a host.
        self.docker_root = root / 'docker-root'
        self.docker_root.mkdir()
        self.compose.write_text('services: {}\n')
        # id -> release (a connected agent) or {'status': 'Disconnected'|'Never connected', 'release': ...}
        self.agents = {'001': release} if agents is None else agents
        self.running = True
        self.stopped_daemons = set()
        self.tags = {service: release for service in w.SERVICES}
        self.repo_digests = True
        self.drop = set()
        self.indexer_status = 'green'
        # Per-component native release reports; None follows the manager's release. The
        # dashboard (plugin package.json) and the indexer (VERSION.json) are separate legs of
        # the "three components run the same release" claim.
        self.dashboard_release = None
        self.indexer_release = None
        self.dashboard_shape = 'plugin'
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
                                               'com.docker.compose.project.config_files': str(self.compose)}},
                         'Mounts': []})
        return rows

    def agent_list(self):
        """agent_control -l: the captured header, manager row and footer around one row per agent."""
        lines = capture('agent_control-l.active.rc0.txt').split('\n')
        rows = [i for i, line in enumerate(lines) if re.match(r'^   ID: [0-9]+,', line)]
        out = lines[:rows[1]]
        for identifier, spec in self.agents.items():
            status = 'Active' if isinstance(spec, str) else spec['status']
            name, address = ('ghost-never', '10.9.9.9') if status == 'Never connected' else ('agent-' + identifier, 'any')
            out.append('   ID: %s, Name: %s, IP: %s, %s' % (identifier, name, address, status))
        return '\n'.join(out + lines[rows[-1] + 1:])

    def agent_info(self, identifier):
        """agent_control -i: the captured block for the agent's state, with only id, name and release substituted."""
        spec = self.agents[identifier]
        status = 'Active' if isinstance(spec, str) else spec['status']
        release = spec if isinstance(spec, str) else spec.get('release')
        text = capture({'Active': 'agent_control-i.active-older.rc0.txt', 'Disconnected': 'agent_control-i.disconnected.rc0.txt',
                        'Never connected': 'agent_control-i.never-connected.rc0.txt'}[status])
        text = re.sub(r'(Agent ID:\s+)[0-9]+', lambda m: m[1] + identifier, text)
        if status != 'Never connected':
            text = re.sub(r'(Agent Name: )\S+', lambda m: m[1] + 'agent-' + identifier, text)
            text = re.sub(r'(Client version:\s+Wazuh v)[0-9.]+', lambda m: m[1] + release, text)
        return text

    def run(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        self.calls.append(argv)
        rc, text = 0, ''
        if argv[:2] == ['docker', 'info']:
            text = str(self.docker_root) if '--format' in argv else ''
        elif argv[:2] == ['docker', 'ps']:
            text = '\n'.join(row['Id'] for row in self.inspect())
        elif argv[-1] == 'info' and 'wazuh-control' in argv[-2]:
            text = re.sub(r'(WAZUH_VERSION="v)[0-9.]+', lambda m: m[1] + self.release, capture('wazuh-control-info.manager.rc0.txt'))
        elif argv[-1] == 'status':
            # Captured on a healthy manager: rc 1 because the optional daemons are intentionally stopped.
            text, rc = capture('wazuh-control-status.manager.rc1.txt'), 1
            for name in self.stopped_daemons:
                text = text.replace('wazuh-%s is running...' % name, 'wazuh-%s not running...' % name)
        elif '-l' in argv:
            text = self.agent_list()
        elif '-i' in argv:
            text = self.agent_info(argv[argv.index('-i') + 1])
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
            # RepoDigests shape: native capture (docker-image-inspect.repo-tags-and-digests.txt), where the
            # official repository digest is the image id's own sha256.
            digests = {True: [repo + '@' + identifier], False: [],
                       'foreign': ['attacker/' + repo.split('/')[1] + '@' + identifier],
                       'malformed': [repo + '@sha256:not-a-digest', repo + ':4.14.1']}[self.repo_digests]
            # Size: B's discover sums the retained images' sizes for backup capacity.
            return [{'Id': identifier, 'RepoDigests': digests, 'Size': 1024}]
        if 'curl' in argv:
            return dict(json.loads(capture('indexer-cluster-health.json')), status=self.indexer_status)
        if argv[-1] == '/usr/share/wazuh-dashboard/plugins/wazuh/package.json':
            if self.dashboard_shape == 'opensearch-root':
                # The dashboard's ROOT package.json (native capture, Wazuh 4.14.9): its own version is the
                # OpenSearch Dashboards release and the Wazuh release hides one level down. A coordinator
                # that read this file would pass on `wazuh.version`; the plugin leg must not.
                return {'name': 'opensearch-dashboards', 'version': '2.19.6', 'wazuh': {'version': self.release}}
            # MODELED: the plugin package.json body was not saved in the native run (only its top-level
            # version equality is proven, by C12 PASS); the dashboard VERSION.json capture is not this file.
            return {'version': self.release if self.dashboard_release is None else self.dashboard_release}
        if argv[-1] == '/usr/share/wazuh-indexer/VERSION.json':
            value = json.loads(capture('indexer-VERSION.json'))
            return dict(value, version=self.release if self.indexer_release is None else self.indexer_release)
        raise AssertionError(argv)
