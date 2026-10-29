#!/usr/bin/env python3
"""Qualify scanner integration controls; never start an AV engine or inference.

Uses an existing synthetic OpenPGP fixture for signature/encryption regressions.
Independent crypto-container journeys are separate F011/F012 evidence; this
command does not silently substitute protocol fixtures for malware detection.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
import subprocess
import time
import uuid

os.umask(0o077)
root = Path(__file__).resolve().parents[1]
os.chdir(root)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--pgp-fixture-reference', required=True)
args = parser.parse_args()
fixture = (root / args.pgp_fixture_reference).resolve()
if not fixture.is_relative_to(root / '.private') or not (fixture / 'manifest.json').is_file():
    raise SystemExit('An existing task-owned protected OpenPGP fixture is required')
fixture_manifest = json.loads((fixture / 'manifest.json').read_text())
age = (datetime.now(timezone.utc) - datetime.fromisoformat(fixture_manifest['observed_at'])).total_seconds()
if fixture_manifest.get('state') != 'passed' or not 0 <= age <= 2700:
    fixture_preflight_error = 'Fixture exceeds the unchanged one-hour signature policy safety window. Refresh via scripts/prepare-pgp-fixture.py --rows 2. Continue independent gates, retaining failed overall status.'
else:
    fixture_preflight_error = None
if (fixture / 'source.csv').read_bytes() != b'account,amount,day\n' + b'00000001,100.01,2026-10-28\n' * 2:
    raise SystemExit('Select the two-row signature fixture for the existing intake regression contract')
for entry in fixture_manifest['files']:
    path = (root / entry['path']).resolve()
    if path.parent != fixture or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
        raise SystemExit('The protected independent fixture manifest does not match its files')
raw = root / 'evidence/raw' / ('scanner-controls-' + uuid.uuid4().hex)
raw.mkdir(parents=True, mode=0o700)
env = dict(os.environ, GOMAXPROCS='1', FREIGHTCTL_TEST_ADMIN_FILE=str(root / '.private/pg-admin.dsn'),
           FREIGHTCTL_TEST_RUNTIME_FILE=str(root / '.private/pg-runtime.dsn'),
           FREIGHTCTL_TEST_PGP_DIR=str(fixture))

def source_hashes():
    paths = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z']).decode().split('\0')
    return [{'path': p, 'sha256': hashlib.sha256((root / p).read_bytes()).hexdigest()}
            for p in sorted(set(paths)) if p and ((root / p).suffix in ('.go', '.sql', '.sh', '.py') or p in ('go.mod', 'go.sum'))]

starting_sources = source_hashes()
packages = subprocess.check_output(['sh', 'scripts/go.sh', 'list', '-p', '1', './...'], env=env).decode().splitlines()
integration_packages = [p for p in packages if p != 'github.com/ctlplne/freightctl/internal/crypto']
commands = [
    ('records', ['python3', 'scripts/check-records.py']),
    ('module-integrity', ['sh', 'scripts/go.sh', 'mod', 'verify']),
    ('vet', ['sh', 'scripts/go.sh', 'vet', '-p', '1', './...']),
    ('unit-race', ['sh', 'scripts/go.sh', 'test', '-p', '1', '-count=1', '-race', './...']),
    ('retained-database-migration', ['sh', 'scripts/go.sh', 'run', '-p', '1', './cmd/freightctl', 'init']),
    ('scanner-postgres-controls-race', ['sh', 'scripts/go.sh', 'test', '-tags=integration', '-p', '1', '-count=1', '-race', '-v', './internal/checks', '-run', 'TestScanner|TestUnavailableMalformedAndDetectedScansNeverBecomeClean']),
    ('postgres-integration-race', ['sh', 'scripts/go.sh', 'test', '-tags=integration', '-p', '1', '-count=1', '-race', '-v', *integration_packages]),
    ('scanner-record-fuzz', ['sh', 'scripts/go.sh', 'test', './internal/scanner', '-fuzz=FuzzClamdRecordAndVersion', '-fuzztime=5s', '-parallel=1']),
    ('csv-contract-fuzz', ['sh', 'scripts/go.sh', 'test', './internal/checks', '-fuzz=FuzzCSVContract', '-fuzztime=5s', '-parallel=1']),
    ('stock-curl-https', ['python3', 'scripts/qualify-https.py']),
    ('stock-openssh-sftp', ['python3', 'scripts/qualify-sftp.py']),
    ('durable-upload-resume', ['python3', 'scripts/qualify-uploads.py']),
    ('durable-outbound-delivery', ['python3', 'scripts/qualify-deliveries.py']),
    ('versioned-workflow-execution', ['python3', 'scripts/qualify-workflows.py']),
    ('assistance-controls-no-inference', ['python3', 'scripts/qualify-assistance.py']),
    ('held-intake-and-csv-checks', ['python3', 'scripts/qualify-intake.py']),
    ('scanner-outage-no-engine', ['python3', 'scripts/qualify-scanner-unavailable.py']),
]
results = []
for name, command in commands:
    start = time.monotonic()
    log = raw / (name + '.log')
    with log.open('wb') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, env=env)
    results.append({'name': name, 'command': command, 'exit_code': result.returncode,
                    'duration_seconds': round(time.monotonic() - start, 3),
                    'native_output': str(log.relative_to(root)),
                    'native_output_sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
    print(name + ': ' + ('passed' if result.returncode == 0 else 'FAILED'), flush=True)
    if result.returncode:
        print(log.read_text()[-4000:], flush=True)
sources = source_hashes()
manifest = {'schema_version': 1, 'started_from': subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip(),
            'source_files': sources, 'sources_unchanged_during_run': starting_sources == sources,
            'observed_at': datetime.now(timezone.utc).isoformat(), 'results': results,
            'scanner_engine_started': False, 'standard_signature_database_loaded': False,
            'malware_detection_qualified': False, 'inference_performed': False, 'local_model_processes_started': 0,
            'fixture_preflight_error': fixture_preflight_error,
            'integration_scope': {'packages': integration_packages, 'existing_pgp_fixture_reference': str(fixture.relative_to(root)),
                                  'not_rerun': 'Unchanged internal/crypto independent Docker/GnuPG journeys: retained F011/F012 evidence. All-package unit/race and real PostgreSQL signature/encryption consumers do run.'},
            'state': 'passed' if not fixture_preflight_error and len(results) == len(commands) and all(x['exit_code'] == 0 for x in results) and starting_sources == sources else 'failed'}
(raw / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
(root / '.private/scanner-controls-current').write_text(str(raw) + '\n')
print(str(raw / 'manifest.json'), flush=True)
if manifest['state'] != 'passed':
    raise SystemExit(1)
