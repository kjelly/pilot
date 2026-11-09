"""Native backend substitute for the manager version-gate graph.

The production coordinator's `central` action (Central.execute, discovery, registry
bound, health parsing) runs for real over the modeled docker/Wazuh commands of
wazuh_models.Docker. The docker engine probe and the sentinel "a stack mutation
was reached" task are modeled. Not native VM evidence.
"""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from wazuh_models import Docker

settings_file, action, *rest = sys.argv[1:]
settings = json.loads(Path(settings_file).read_text())


def event(name, **fields):
    with open(settings['events'], 'a') as out:
        out.write(json.dumps(dict(action=name, **fields)) + '\n')


event(action)
if action == 'docker-info':
    # The pre-flight `docker info` command: rc 1 when the engine is absent.
    sys.exit(0 if settings['docker_up'] else 1)
if action == 'mutation':
    print('{}')
    sys.exit(0)

spec = importlib.util.spec_from_file_location('production', settings['library'])
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
root = Path(tempfile.mkdtemp(prefix='wazuh-gate-model-'))
docker = Docker(w, root, settings['stack_release'], settings.get('agents'))
if settings['stack'] == 'absent':
    docker.drop = set(w.SERVICES)
docker.dashboard_release = settings.get('dashboard_release')
docker.indexer_release = settings.get('indexer_release')
if settings.get('stopped_daemon'):
    docker.stopped_daemons.add(settings['stopped_daemon'])
real_run, real_json = docker.run, docker.json


def recording(method):
    def call(argv, **kwargs):
        event('docker', argv=[str(a) for a in argv][:3])
        return method(argv, **kwargs)
    return call


docker.run, docker.json = recording(real_run), recording(real_json)
original = w.Central.__init__
w.Central.__init__ = lambda self, managed_root=None, **kwargs: original(self, managed_root=docker.managed, **kwargs)
w.is_root = lambda: True
w.Runner = lambda: docker
w.ROOT = root / 'ledger'
if '--preview-tools-json' in rest:
    # The check-mode preview capability (pinned /run tool closure) is attested and tested by
    # wazuh_preview_tools_test.py; this harness is about the gate's decisions, so the attestation is modeled.
    w.preview_tools = lambda *args, **kwargs: {}
    w.preview_attestation = lambda *args, **kwargs: {}
sys.argv = ['wazuh-transaction.py', action, *rest]
if '--owner' in rest:
    # The production play claims the host-wide writer before the central entry point; the model does the same
    # for the same owner so the coordinator's ownership check is exercised, not bypassed.
    w.HostWriter().claim(rest[rest.index('--owner') + 1], 'central', 'apply')
captured = io.StringIO()
with contextlib.redirect_stdout(captured):
    status = w.main()
text = captured.getvalue()
print(text, end='')
sys.exit(status)
