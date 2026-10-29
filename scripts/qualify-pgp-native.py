#!/usr/bin/env python3
"""Exercise actual native peer isolation, pinned input and low-budget termination."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import shutil
import sys
import subprocess
import time
import uuid

os.umask(0o077)
root = Path(__file__).resolve().parents[1]
os.chdir(root)
config = Path(os.environ['FREIGHTCTL_GNUPG_NATIVE_CONFIG']).resolve(strict=True)
spec = importlib.util.spec_from_file_location('freightctl_native_peer', root / 'scripts/pgp-native-peer.py')
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)
run = 'native-peer-constraints-' + uuid.uuid4().hex
private, raw = root / '.private' / run, root / 'evidence/raw' / run
private.mkdir(mode=0o700)
raw.mkdir(parents=True, mode=0o700)
steps = []

def ref(p):
    return {'reference': str(p.relative_to(root)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}

def rejected(name, path):
    try:
        peer.configuration(path)
    except ValueError:
        steps.append({'name': name, 'state': 'refused before any native process'})
    else:
        raise AssertionError(name + ' was accepted')

metadata = peer.configuration(config)
original = config.read_bytes()
# A world/group-readable configuration cannot select an executable runtime.
p = private / 'public-config.json'
p.write_bytes(original)
p.chmod(0o644)
rejected('broad-config-permissions', p)
p = private / 'modified-runtime.json'
x = json.loads(original)
x['runtime_files'][0]['sha256'] = '0' * 64
p.write_text(json.dumps(x))
rejected('changed-native-library-digest', p)
p = private / 'outside-cache.json'
x = json.loads(original)
x['binaries'][0]['path'] = '/usr/bin/true'
p.write_text(json.dumps(x))
rejected('executable-outside-task-cache', p)
forbidden = private / 'forbidden'
forbidden.write_bytes(b'private fixture must stay unreadable to the peer\n')
write_probe = private / 'must-not-be-created'
# A live listener distinguishes a policy refusal from an unavailable endpoint.
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    job = {'config': str(config), 'metrics': str(raw / 'sandbox-metrics.json'), 'operation': 'probe',
           'probe_read': str(forbidden), 'probe_write': str(write_probe), 'probe_port': listener.getsockname()[1],
           'probe_alias': '/System/Volumes/Data' + str(forbidden), 'probe_signal_pid': os.getpid()}
    peer.run(job)
assert not write_probe.exists()
steps.append({'name': 'live-network-private-files-and-data-volume-alias-denied', 'state': 'passed', 'metrics': ref(raw / 'sandbox-metrics.json')})
job = {'config': str(config), 'metrics': str(raw / 'watchdog-metrics.json'), 'operation': 'watchdog-probe'}
try:
    peer.run(job, max_rss=1 << 20)
except RuntimeError as e:
    assert 'RSS exceeded' in str(e), str(e)
else:
    raise AssertionError('tiny RSS budget did not terminate the worker')
watchdog = json.loads((raw / 'watchdog-metrics.json').read_text())
assert watchdog['state'] == 'failed' and watchdog['cleanup_process_group_empty']
steps.append({'name': 'tiny-budget-terminates-real-worker-and-removes-its-process-group', 'state': 'passed', 'expected_failure_metrics': ref(raw / 'watchdog-metrics.json')})
# Kill the real controller, just as an outer test timeout can. The worker must
# independently notice parent death and remove its own native process group.
crash_metrics = raw / 'parent-death-metrics.json'
program = "import runpy; p=runpy.run_path('scripts/pgp-native-peer.py'); p['run'](" + repr({'config': str(config), 'metrics': str(crash_metrics), 'operation': 'parent-death-probe'}) + ")"
with (raw / 'parent-death.log').open('wb') as log:
    controller = subprocess.Popen([sys.executable, '-c', program], stdout=log, stderr=log)
    lifecycle_path = crash_metrics.with_suffix('.lifecycle.json')
    try:
        for _ in range(100):
            if lifecycle_path.exists():
                lifecycle = json.loads(lifecycle_path.read_text())
                break
            assert controller.poll() is None, 'controller exited before worker launch'
            time.sleep(0.02)
        else:
            raise AssertionError('controller did not record its owned process group')
        assert lifecycle['controller_pid'] == controller.pid
        scratch = Path(lifecycle['scratch'])
        for _ in range(100):
            ready = scratch / 'parent-death-ready.json'
            if ready.exists():
                agent_pid = json.loads(ready.read_text())['agent_pid']
                break
            assert controller.poll() is None, 'controller exited before its actual agent was ready'
            time.sleep(0.02)
        else:
            raise AssertionError('native agent did not become ready')
        members = [row.split() for row in subprocess.check_output(['/bin/ps', '-axo', 'pid=,pgid=']).decode().splitlines()]
        assert [str(agent_pid), str(lifecycle['child_process_group'])] in members, 'native agent escaped its worker process group'
        controller.kill()
        controller.wait(timeout=3)
        time.sleep(0.5)
        groups = subprocess.check_output(['/bin/ps', '-axo', 'pgid=']).decode().split()
        assert str(lifecycle['child_process_group']) not in groups, 'worker survived controller death'
        assert scratch.parent == Path('/private/tmp') and scratch.name.startswith('freightctl-gpg-')
        assert scratch.stat().st_uid == os.getuid() and scratch.stat().st_mode & 0o077 == 0
        request = json.loads((scratch / 'job.json').read_text())
        assert request['controller_pid'] == controller.pid and request['metrics'] == str(crash_metrics)
        shutil.rmtree(scratch)
    finally:
        if controller.poll() is None:
            controller.kill()
            controller.wait(timeout=3)
        if 'lifecycle' in locals():
            peer.terminate_group(lifecycle['child_process_group'])
steps.append({'name': 'abrupt-controller-death-stops-real-worker-and-gnupg-agent-within-half-a-second', 'state': 'passed',
              'lifecycle': ref(lifecycle_path), 'exact_task_scratch_removed_after_group_exit': True})
assert config.read_bytes() == original
manifest = {'schema_version': 1, 'state': 'passed', 'observed_at': datetime.now(timezone.utc).isoformat(),
            'starting_commit': subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),
            'source_files': [ref(root / p) for p in ['scripts/pgp-native-peer.py', 'scripts/qualify-pgp-native.py']],
            'acquisition_manifest': ref(config), 'gpg_version': metadata['version'], 'steps': steps,
            'inference_performed': False, 'local_model_processes_started': 0, 'scanner_engine_started': False,
            'limits': ['Native macOS test-peer isolation only; not production worker isolation or a native Linux/Windows test.',
                       'RSS is sampled for the child process group; observer/OS memory and unsampled peaks are not a hard kernel cap.']}
(raw / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
(root / '.private/native-peer-constraints-current').write_text(str(raw) + '\n')
print(raw / 'manifest.json', flush=True)
