#!/usr/bin/env python3
"""Publish only allowlisted qualification outcomes, never raw native manifests."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re

SUITES = ('collections', 'arrivals', 'schedules', 'routing')
BOUND = 8 << 20


def summarize(path, expected_commit):
    if path.is_symlink() or not path.is_file():
        raise ValueError('unsafe or missing manifest')
    with path.open('rb') as source:
        data = source.read(BOUND + 1)
    if len(data) > BOUND:
        raise ValueError('manifest exceeds bound')
    manifest = json.loads(data)
    if type(manifest.get('schema_version')) is not int or manifest['schema_version'] != 1 or manifest.get('state') not in ('passed', 'failed'):
        raise ValueError('invalid manifest state')
    commit = manifest.get('starting_commit')
    if not isinstance(commit, str) or not re.fullmatch('[0-9a-f]{40}', commit) or commit != expected_commit:
        raise ValueError('manifest belongs to another commit')
    for key in ('sources_unchanged_during_run', 'isolated_database_removed', 'inference_performed', 'scanner_engine_started'):
        if type(manifest.get(key)) is not bool:
            raise ValueError('invalid outcome flag')
    sources, steps, cleanup = manifest.get('source_sha256'), manifest.get('steps'), manifest.get('cleanup_failures')
    if not isinstance(sources, dict) or not 1 <= len(sources) <= 10000:
        raise ValueError('invalid source inventory')
    if any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value) for value in sources.values()):
        raise ValueError('invalid source hash')
    if not isinstance(steps, list) or not 1 <= len(steps) <= 10000 or not isinstance(cleanup, list) or len(cleanup) > 100:
        raise ValueError('invalid step inventory')
    mismatches = 0
    for step in steps:
        actual, expected = step.get('exit_code'), step.get('expected_exit_code')
        if type(actual) is not int or type(expected) is not int:
            raise ValueError('incomplete command outcome')
        mismatches += actual != expected
    outputs, duration = manifest.get('output_artifacts_verified'), manifest.get('duration_seconds')
    if type(outputs) is not int or not 0 <= outputs <= 100000:
        raise ValueError('invalid output count')
    if type(duration) not in (int, float) or not math.isfinite(duration) or not 0 <= duration <= 86400:
        raise ValueError('invalid duration')
    if 'output_closure_failure' not in manifest or 'failure' not in manifest:
        raise ValueError('missing evidence closure')
    complete = (manifest['state'] == 'passed' and manifest['sources_unchanged_during_run']
                and manifest['isolated_database_removed'] and not mismatches and not cleanup
                and outputs >= 2 * len(steps) and manifest['output_closure_failure'] is None and manifest['failure'] is None
                and not manifest['inference_performed'] and not manifest['scanner_engine_started'])
    return {'state': 'passed' if complete else 'failed', 'source_commit': commit,
            'manifest_sha256': hashlib.sha256(data).hexdigest(),
            'source_inputs': len(sources), 'sources_unchanged': manifest['sources_unchanged_during_run'],
            'recorded_commands': len(steps), 'unexpected_command_exits': mismatches,
            'verified_output_artifacts': outputs, 'output_closure_passed': manifest.get('output_closure_failure') is None,
            'cleanup_failures': len(cleanup), 'isolated_database_removed': manifest['isolated_database_removed'],
            'duration_seconds': duration, 'inference_performed': manifest['inference_performed'],
            'scanner_engine_started': manifest['scanner_engine_started']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('suites', nargs='+', choices=SUITES)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    import subprocess
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root).decode().strip()
    raw = root / 'evidence/raw'
    results = {}
    for suite in args.suites:
        paths = list(raw.glob(suite + '-*/manifest.json'))
        try:
            if len(paths) != 1 or paths[0].parent.is_symlink():
                raise ValueError('one exact manifest required')
            results[suite] = summarize(paths[0], commit)
        except (ValueError, OSError, TypeError, AttributeError):
            # Manifest data and paths can contain protected or hostile text.
            results[suite] = {'state': 'missing_or_invalid', 'source_commit': commit}
    rendered = json.dumps(results, indent=2, allow_nan=False)
    print(rendered)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as output:
            output.write('Qualification outcomes (safe fields only)\n\n```json\n' + rendered + '\n```\n')
    return 0 if all(r['state'] == 'passed' for r in results.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
