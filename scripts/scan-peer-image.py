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


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


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
    cache.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    phase = 'checkout'
    steps = []

    def command(name, arguments, timeout, *, check=True):
        stdout, stderr = private/(name+'.stdout'), private/(name+'.stderr')
        try:
            with stdout.open('xb') as out, stderr.open('xb') as err:
                result = subprocess.run(arguments, stdout=out, stderr=err, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            steps.append({'phase': name, 'exit_code': None, 'incomplete': True,
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
                  '--network', network,
                  '--label', 'freightctl.purpose=peer-image-scan',
                  '--label', 'freightctl.scan='+session,
                  '--mount', 'type=bind,src='+str(cache)+',dst=/cache'+('' if writable_cache else ',readonly')]
        for mount in mounts:
            limits.extend(['--mount', mount])
        _, created = command(name+'-create', ['docker', 'create', '--name',
                'freightctl-peer-image-'+session+'-'+name, *limits, gate.SCANNER_IMAGE, *arguments], 30)
        ident = created.read_text().strip()
        if not re.fullmatch('[0-9a-f]{64}', ident):
            raise RuntimeError('container-identity-invalid')
        try:
            return command(name, ['docker', 'start', '--attach', ident], timeout)
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
        manifest = {'schema_version': 1, 'source_commit': commit, 'image_id': image_id,
                    'architecture': args.architecture, 'state': result['state'], 'steps': steps,
                    'summary_sha256': summary_sha, 'scanner_inspect_sha256': digest(scanner_inspect),
                    'feed_metadata_sha256': metadata_sha, 'runtime_qualification': False}
        record = private/'manifest.json'
        record.write_text(json.dumps(manifest, indent=2)+'\n')
        # Only this verifier's own bounded allowlisted summary reaches stdout.
        result['manifest_sha256'] = digest(record)
        print(json.dumps(result, sort_keys=True))
        return code
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
        record = private/'failure.json'
        record.write_text(json.dumps({'schema_version': 1, 'state': 'failed', 'phase': phase, 'steps': steps}, indent=2)+'\n')
        print(json.dumps({'state': 'failed', 'reason': 'native-peer-image-scan-failed',
                          'phase': phase, 'manifest_sha256': digest(record)}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
