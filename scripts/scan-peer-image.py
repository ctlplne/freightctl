#!/usr/bin/env python3
"""GitHub-only same-image scan, without exposing raw reports or Docker sockets."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('peer_image_summary', ROOT/'scripts/ci-peer-image-summary.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

COMMAND_PHASES = frozenset(('checkout', 'image-identity', 'image-archive', 'scanner-image',
    'scanner-identity', 'input-closure', 'enforcing-summary', 'scratch-format', 'scratch-mount',
    'scratch-mount-identity', 'scratch-loop-identity', 'scratch-unmount',
    'scratch-cleanup-mount-identity', 'scratch-cleanup-loop-identity', *(
        stage + suffix for stage in ('feed-download', 'scanner-version', 'image-scan')
        for suffix in ('', '-create', '-state', '-cleanup'))))
DIAGNOSTICS = {
    'unsupported-option': (b'unknown flag', b'flag provided but not defined'),
    'registry-rate-limit': (b'toomanyrequests', b'too many requests', b'429 too many'),
    'registry-authorization': (b'unauthorized', b'authentication required', b'denied: requested access'),
    'registry-tls': (b'x509:', b'certificate verify failed', b'certificate signed by unknown authority'),
    'storage-capacity': (b'no space left on device', b'disk quota exceeded'),
    'filesystem-refused': (b'permission denied', b'read-only file system'),
    'network-unavailable': (b'no such host', b'network is unreachable', b'connection refused', b'tls handshake timeout'),
    'feed-schema': (b'version of db schema', b'old db schema', b'db schema version does not match'),
}


def failure_observation(steps, private):
    """Hash-bound diagnostic clues only; never authority or an inferred cause."""
    result = {'command_phase': 'not-recorded', 'exit_code': None,
              'category': 'unrecognized-diagnostic', 'stdout_sha256': None, 'stderr_sha256': None}
    for step in reversed(steps):
        if not isinstance(step, dict):
            continue
        code = step.get('exit_code')
        if not (type(code) is int and -128 <= code <= 255 and code != 0 or step.get('incomplete') is True):
            continue
        name = step.get('phase')
        if isinstance(name, str) and name.endswith('-state'):
            # Diagnostic read failures cannot replace the original failed
            # execution. Missing/unbound state simply proves no OOM fact.
            continue
        if not isinstance(name, str) or name not in COMMAND_PHASES:
            return result
        result['command_phase'] = name
        result['exit_code'] = code if type(code) is int and -128 <= code <= 255 else None
        for stream in ('stdout', 'stderr'):
            value = step.get(stream+'_sha256')
            if isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value):
                result[stream+'_sha256'] = value
        state = container_failure_state(steps, private, name)
        if state is not None:
            result['container_state'] = state
        if step.get('timed_out') is True:
            result['category'] = 'deadline-exceeded'
            return result
        if (state is not None and state['oom_killed'] and not state['running']
                and state['exit_code'] == result['exit_code']):
            result['category'] = 'container-oom'
            return result
        try:
            path = private/(name+'.stderr')
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 << 20:
                return result
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != result['stderr_sha256']:
                return result
            raw = raw.lower()
            matches = {kind for kind, patterns in DIAGNOSTICS.items() if any(p in raw for p in patterns)}
            if len(matches) == 1:
                result['category'] = matches.pop()
        except OSError:
            pass
        return result
    return result


def container_failure_state(steps, private, phase):
    """Only exact failed-container state, before deletion, can describe OOM."""
    if phase not in ('feed-download', 'scanner-version', 'image-scan'):
        return None
    for step in reversed(steps):
        if not isinstance(step, dict) or step.get('phase') != phase+'-state':
            continue
        try:
            path = private/(phase+'-state.stdout')
            if step.get('exit_code') != 0 or type(step.get('exit_code')) is not int or path.is_symlink():
                return None
            state, actual = gate.load(path, 1 << 20)
            if (actual != step.get('stdout_sha256') or not isinstance(state, dict)
                    or type(state.get('OOMKilled')) is not bool or type(state.get('Running')) is not bool
                    or type(state.get('ExitCode')) is not int or not 0 <= state['ExitCode'] <= 255):
                return None
            return {'oom_killed': state['OOMKilled'], 'running': state['Running'],
                'exit_code': state['ExitCode'], 'state_sha256': actual}
        except (OSError, ValueError, TypeError, KeyError):
            return None
    return None


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class BoundedScratch:
    """A private 2GiB ext4 volume; temporary archives consume disk, not RAM."""
    size = 2 << 30

    def __init__(self, private):
        self.backing = private/'scratch.ext4'
        self.root = private/'scratch'
        self.root.mkdir(mode=0o700)
        with self.backing.open('xb') as stream:
            stream.truncate(self.size)
            stream.flush()
            os.fsync(stream.fileno())
        self.backing.chmod(0o600)
        self.attempted = False
        self.mounted = False
        self.cleanup_attempted = False

    def identity(self, command, cleanup=False):
        prefix = 'scratch-cleanup-' if cleanup else 'scratch-'
        code, output = command(prefix+'mount-identity', ['findmnt', '--json', '--mountpoint',
            str(self.root), '--output', 'SOURCE,FSTYPE,TARGET,OPTIONS'], 15, check=False)
        if code == 1 and not self.mounted:
            return False
        gate.require(code == 0)
        value, _ = gate.load(output, 1 << 20)
        gate.require(isinstance(value, dict))
        filesystems = value.get('filesystems')
        gate.require(isinstance(filesystems, list) and len(filesystems) == 1)
        mount = filesystems[0]
        gate.require(isinstance(mount, dict) and mount.get('fstype') == 'ext4'
                     and mount.get('target') == str(self.root)
                     and isinstance(mount.get('source'), str)
                     and re.fullmatch('/dev/loop[0-9]+', mount['source']))
        options = mount.get('options', '')
        gate.require(isinstance(options, str) and {'rw', 'nodev', 'nosuid', 'noexec'} <= set(options.split(',')))
        _, output = command(prefix+'loop-identity', ['losetup', '--json', '--list', '--associated',
            str(self.backing), '--output', 'NAME,BACK-FILE'], 15)
        value, _ = gate.load(output, 1 << 20)
        gate.require(isinstance(value, dict))
        loops = value.get('loopdevices')
        gate.require(isinstance(loops, list) and len(loops) == 1
                     and isinstance(loops[0], dict)
                     and loops[0].get('name') == mount['source']
                     and loops[0].get('back-file') == str(self.backing)
                     and self.backing.is_file() and not self.backing.is_symlink()
                     and self.backing.stat().st_size == self.size)
        return True

    def prepare(self, command):
        command('scratch-format', ['mkfs.ext4', '-q', '-F', '-m', '0', '-E',
            'root_owner='+str(os.getuid())+':'+str(os.getgid()), str(self.backing)], 30)
        # Mark before invoking mount: even a timed-out command needs exact
        # ownership inspection before deciding whether cleanup is necessary.
        self.attempted = True
        command('scratch-mount', ['sudo', '-n', 'mount', '--types', 'ext4', '--options',
            'loop,nodev,nosuid,noexec', '--source', str(self.backing), '--target', str(self.root)], 30)
        self.mounted = True
        self.identity(command)
        self.root.chmod(0o700)
        for name in ('cache', 'tmp'):
            (self.root/name).mkdir(mode=0o700)

    def close(self, command):
        if not self.attempted or self.cleanup_attempted:
            return
        self.cleanup_attempted = True
        if self.identity(command, cleanup=True):
            command('scratch-unmount', ['sudo', '-n', 'umount', '--', str(self.root)], 30)
        self.mounted = False
        self.attempted = False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--architecture', required=True, choices=('amd64', 'arm64'))
    args = parser.parse_args()
    commit = os.environ.get('GITHUB_SHA', '')
    expected_machine = {'amd64': 'x86_64', 'arm64': 'aarch64'}[args.architecture]
    # No Docker, scanner download, model or database action precedes this check.
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux'
            or platform.machine() != expected_machine or not re.fullmatch('[0-9a-f]{40}', commit)
            or ',' in str(ROOT)):
        print(json.dumps({'state': 'failed', 'reason': 'native-github-peer-scan-required'}))
        return 2
    os.chdir(ROOT)
    os.umask(0o077)
    session = uuid.uuid4().hex
    private = ROOT/'.private'/('freightctl-peer-image-scan-'+session)
    private.mkdir(mode=0o700)
    cache, output = private/'cache', private/'output'
    output.mkdir(mode=0o700)
    phase = 'checkout'
    steps = []
    scratch = None

    def command(name, arguments, timeout, *, check=True):
        stdout, stderr = private/(name+'.stdout'), private/(name+'.stderr')
        try:
            with stdout.open('xb') as out, stderr.open('xb') as err:
                result = subprocess.run(arguments, stdout=out, stderr=err, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as failure:
            steps.append({'phase': name, 'exit_code': None, 'incomplete': True,
                          'timed_out': isinstance(failure, subprocess.TimeoutExpired),
                          'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)})
            raise
        if stdout.stat().st_size > 32 << 20 or stderr.stat().st_size > 32 << 20:
            raise RuntimeError('private-output-bound')
        steps.append({'phase': name, 'exit_code': result.returncode,
                      'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)})
        if check and result.returncode != 0:
            raise RuntimeError('command-failed')
        return result.returncode, stdout

    def container(name, arguments, *, network, writable_cache=False, mounts=(), timeout=60):
        limits = ['--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                  '--memory=1g', '--memory-swap=1g', '--cpus=1', '--pids-limit=128',
                  '--user', str(os.getuid())+':'+str(os.getgid()),
                  '--tmpfs', '/tmp:rw,noexec,nosuid,size=256m', '--workdir', '/tmp',
                  '--env', 'GOMAXPROCS=1', '--env', 'GOMEMLIMIT=768MiB',
                  '--env', 'TMPDIR=/scratch',
                  '--network', network,
                  '--label', 'freightctl.purpose=peer-image-scan',
                  '--label', 'freightctl.scan='+session,
                  '--mount', 'type=bind,src='+str(cache)+',dst=/cache'+('' if writable_cache else ',readonly'),
                  '--mount', 'type=bind,src='+str(scratch.root/'tmp')+',dst=/scratch']
        for mount in mounts:
            limits.extend(['--mount', mount])
        _, created = command(name+'-create', ['docker', 'create', '--name',
                'freightctl-peer-image-'+session+'-'+name, *limits, gate.SCANNER_IMAGE, *arguments], 30)
        ident = created.read_text().strip()
        if not re.fullmatch('[0-9a-f]{64}', ident):
            raise RuntimeError('container-identity-invalid')
        try:
            return command(name, ['docker', 'start', '--attach', ident], timeout)
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
            try:
                # Capture only this exact created container, before rm destroys
                # the evidence. Raw State.Error/PID/timestamps remain private.
                command(name+'-state', ['docker', 'inspect', '--format', '{{json .State}}', ident], 15, check=False)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
                pass
            raise
        finally:
            # Only the exact ID returned by this invocation is ever removed.
            command(name+'-cleanup', ['docker', 'rm', '--force', ident], 30)

    try:
        _, head = command('checkout', ['git', 'rev-parse', 'HEAD'], 15)
        if head.read_text().strip() != commit:
            raise RuntimeError('source-identity-invalid')
        phase = 'image-identity'
        _, inspected = command(phase, ['docker', 'image', 'inspect', 'freightctl-openpgp-peer:6.3.2-r1'], 30)
        image, _ = gate.load(inspected, 1 << 20)
        gate.require(isinstance(image, list) and len(image) == 1 and isinstance(image[0], dict))
        image_id = image[0].get('Id', '')
        gate.require(isinstance(image_id, str) and gate.DIGEST.fullmatch(image_id))
        gate.require(image[0].get('Architecture') == args.architecture and image[0].get('Os') == 'linux')
        config = image[0].get('Config', {})
        gate.require(config.get('Labels', {}).get('freightctl.source') == commit)
        phase = 'image-archive'
        archive = private/'peer.tar'
        command(phase, ['docker', 'image', 'save', '--output', str(archive), image_id], 120)
        gate.require(0 < archive.stat().st_size <= 2 << 30)
        archive_sha = digest(archive)
        phase = 'scanner-image'
        command(phase, ['docker', 'pull', gate.SCANNER_IMAGE], 240)
        _, scanner_inspect = command('scanner-identity', ['docker', 'image', 'inspect', gate.SCANNER_IMAGE], 30)
        scanner, _ = gate.load(scanner_inspect, 1 << 20)
        gate.require(isinstance(scanner, list) and len(scanner) == 1
                     and scanner[0].get('Architecture') == args.architecture and scanner[0].get('Os') == 'linux')
        phase = 'scratch-volume'
        scratch = BoundedScratch(private)
        scratch.prepare(command)
        cache = scratch.root/'cache'
        phase = 'feed-download'
        common = ['--cache-dir', '/cache', '--config', '/dev/null']
        container(phase, [*common, 'image', '--download-db-only', '--db-repository',
                  'ghcr.io/aquasecurity/trivy-db:2', '--no-progress', '--disable-telemetry',
                  '--skip-version-check', '--timeout', '4m'], network='bridge', writable_cache=True, timeout=300)
        feed_database, feed_metadata = cache/'db/trivy.db', cache/'db/metadata.json'
        gate.require(feed_database.is_file() and 0 < feed_database.stat().st_size <= 1 << 30)
        gate.require(feed_metadata.is_file() and 0 < feed_metadata.stat().st_size <= 1 << 20)
        feed_sha, metadata_sha = digest(feed_database), digest(feed_metadata)
        phase = 'scanner-version'
        _, version = container(phase, [*common, 'version', '--format', 'json'], network='none')
        phase = 'image-scan'
        # No Docker socket, registry, repo config, ignore file, VEX or credentials
        # are available here. Scan the immutable saved image, not a mutable tag.
        container(phase, [*common, 'image', '--input', '/input/peer.tar', '--scanners', 'vuln',
                  '--pkg-types', 'os,library', '--list-all-pkgs', '--show-suppressed',
                  '--ignorefile', '/dev/null', '--ignore-unfixed=false',
                  '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--parallel', '1',
                  '--skip-db-update', '--skip-java-db-update', '--offline-scan',
                  '--skip-version-check', '--disable-telemetry', '--no-progress',
                  '--cache-backend', 'memory', '--format', 'json', '--output', '/output/report.json',
                  '--exit-code', '0', '--exit-on-eol', '2', '--timeout', '10m'], network='none',
                  mounts=['type=bind,src='+str(archive)+',dst=/input/peer.tar,readonly',
                          'type=bind,src='+str(output)+',dst=/output'], timeout=660)
        phase = 'input-closure'
        gate.require(feed_sha == digest(feed_database) and metadata_sha == digest(feed_metadata)
                     and archive_sha == digest(archive))
        phase = 'enforcing-summary'
        code, summary = command(phase, [sys.executable, str(ROOT/'scripts/ci-peer-image-summary.py'),
                '--report', str(output/'report.json'), '--version', str(version), '--image', str(inspected),
                '--feed-database', str(feed_database), '--archive', str(archive),
                '--commit', commit, '--architecture', args.architecture], 60, check=False)
        result, summary_sha = gate.load(summary, 1 << 20)
        gate.require(code in (0, 1) and isinstance(result, dict)
                     and result.get('state') == ('passed' if code == 0 else 'failed'))
        phase = 'scratch-cleanup'
        scratch.close(command)
        manifest = {'schema_version': 1, 'source_commit': commit, 'image_id': image_id,
                    'architecture': args.architecture, 'state': result['state'], 'steps': steps,
                    'summary_sha256': summary_sha, 'scanner_inspect_sha256': digest(scanner_inspect),
                    'feed_metadata_sha256': metadata_sha, 'scratch_bytes': BoundedScratch.size,
                    'scratch_unmounted': not scratch.attempted, 'runtime_qualification': False}
        record = private/'manifest.json'
        record.write_text(json.dumps(manifest, indent=2)+'\n')
        # Only this verifier's own bounded allowlisted summary reaches stdout.
        result['manifest_sha256'] = digest(record)
        result['scratch_bytes'] = BoundedScratch.size
        result['scratch_cleanup'] = 'unmounted'
        print(json.dumps(result, sort_keys=True))
        return code
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
        if scratch is not None and scratch.attempted:
            try:
                scratch.close(command)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
                # Refuse to unmount a foreign or unproven device. This remains
                # a failed job; the disposable runner is the final boundary.
                pass
        cleanup = 'not-created' if scratch is None else 'unmounted' if not scratch.attempted else 'unproven'
        record = private/'failure.json'
        record.write_text(json.dumps({'schema_version': 1, 'state': 'failed', 'phase': phase,
            'steps': steps, 'scratch_cleanup': cleanup, 'scratch_bytes': BoundedScratch.size}, indent=2)+'\n')
        print(json.dumps({'state': 'failed', 'reason': 'native-peer-image-scan-failed',
                          'phase': phase, 'manifest_sha256': digest(record),
                          'scratch_cleanup': cleanup,
                          'command': failure_observation(steps, private)}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
