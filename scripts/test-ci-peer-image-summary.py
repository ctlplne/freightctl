#!/usr/bin/env python3
"""Synthetic verifier/exit/privacy contracts; never run Docker or a scanner."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('peer_image_summary', HERE / 'ci-peer-image-summary.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
NOW = datetime(2026, 11, 4, 18, tzinfo=timezone.utc)
COMMIT = 'a' * 40
IMAGE = 'sha256:' + 'b' * 64
PRIVATE = 'credential-and-private-path-must-never-appear'


def inputs(now=NOW, arch='amd64'):
    stamp = lambda delta: (now + delta).isoformat()
    report = {'SchemaVersion': 2, 'Trivy': {'Version': '0.76.1'},
              'ArtifactType': 'container_image', 'CreatedAt': stamp(timedelta()),
              'Metadata': {'ImageID': IMAGE, 'OS': {'Family': 'debian', 'Name': '12'},
                           'ImageConfig': {'architecture': arch, 'os': 'linux'}},
              'Results': [{'Class': 'os-pkgs', 'Type': 'debian', 'Target': PRIVATE,
                           'Packages': [{'Name': PRIVATE, 'Version': PRIVATE}]},
                          {'Class': 'lang-pkgs', 'Type': 'node-pkg', 'Target': PRIVATE,
                           'Packages': [{'Name': 'openpgp', 'Version': '6.3.2'}]}]}
    version = {'Version': '0.76.1', 'VulnerabilityDB': {'Version': 2,
               'UpdatedAt': stamp(-timedelta(hours=1)), 'NextUpdate': stamp(timedelta(hours=5)),
               'DownloadedAt': stamp(-timedelta(minutes=2))}}
    image = [{'Id': IMAGE, 'Architecture': arch, 'Os': 'linux',
              'Config': {'User': '65532:65532', 'Labels': {
                  'freightctl.purpose': 'openpgp-interoperability', 'freightctl.source': COMMIT,
                  'freightctl.workspace': PRIVATE}}}]
    return report, version, image


class ImageReportContracts(unittest.TestCase):
    def check(self, report=None, version=None, image=None, **kwargs):
        original = inputs()
        return gate.summarize(report if report is not None else original[0],
                              version if version is not None else original[1],
                              image if image is not None else original[2],
                              kwargs.get('commit', COMMIT), kwargs.get('architecture', 'amd64'), NOW)

    def test_both_native_architectures_and_exact_image(self):
        for arch in ('amd64', 'arm64'):
            with self.subTest(arch=arch):
                r, v, i = inputs(arch=arch)
                result = self.check(r, v, i, architecture=arch)
                self.assertEqual(result['state'], 'passed')
                self.assertEqual(result['image_id'], IMAGE)
                self.assertEqual(result['package_counts'], {'os-pkgs': 1, 'lang-pkgs': 1})
                self.assertNotIn(PRIVATE, json.dumps(result))

    def test_every_severity_is_counted_and_unknown_high_critical_fail(self):
        for severity in gate.SEVERITIES:
            with self.subTest(severity=severity):
                r, v, i = inputs()
                r['Results'][0]['Vulnerabilities'] = [{'Severity': severity, 'VulnerabilityID': 'CVE-2026-12345',
                    'Description': PRIVATE, 'PkgName': PRIVATE, 'FixedVersion': ''}]
                result = self.check(r, v, i)
                self.assertEqual(result['severities'][severity], 1)
                self.assertEqual(result['state'], 'failed' if severity in ('UNKNOWN', 'HIGH', 'CRITICAL') else 'passed')
                self.assertEqual(result['advisory_ids'], ['CVE-2026-12345'])
                self.assertNotIn(PRIVATE, json.dumps(result))

    def test_all_suppression_fails_even_without_visible_vulnerability(self):
        r, v, i = inputs()
        r['Results'][0]['ExperimentalModifiedFindings'] = [{'Private': PRIVATE}]
        result = self.check(r, v, i)
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['suppressed_findings'], 1)
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_advisory_output_is_fixed_format_and_bounded_without_changing_counts(self):
        r, v, i = inputs()
        r['Results'][0]['Vulnerabilities'] = [{'Severity': 'HIGH', 'VulnerabilityID': f'CVE-2026-{10000+n}'} for n in range(70)]
        r['Results'][0]['Vulnerabilities'].append({'Severity': 'HIGH', 'VulnerabilityID': PRIVATE})
        result = self.check(r, v, i)
        self.assertEqual(result['severities']['HIGH'], 71)
        self.assertEqual(len(result['advisory_ids']), 50)
        self.assertEqual(result['additional_advisory_ids'], 20)
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_metadata_foreign_image_platform_scanner_and_source_refusals(self):
        mutations = [
            lambda r, v, i: r.update(SchemaVersion=True),
            lambda r, v, i: r.update(SchemaVersion=1),
            lambda r, v, i: r.update(ArtifactType='filesystem'),
            lambda r, v, i: r['Trivy'].update(Version='other'),
            lambda r, v, i: r['Metadata'].update(ImageID='sha256:'+'c'*64),
            lambda r, v, i: r['Metadata']['ImageConfig'].update(architecture='arm64'),
            lambda r, v, i: r['Metadata']['ImageConfig'].update(os='windows'),
            lambda r, v, i: r['Metadata']['OS'].update(Family='alpine'),
            lambda r, v, i: r['Metadata']['OS'].update(Name='11'),
            lambda r, v, i: r['Metadata']['OS'].update(EOSL=True),
            lambda r, v, i: i.append(copy.deepcopy(i[0])),
            lambda r, v, i: i[0].update(Id='invalid'),
            lambda r, v, i: i[0].update(Architecture='arm64'),
            lambda r, v, i: i[0]['Config'].update(User='0'),
            lambda r, v, i: i[0]['Config']['Labels'].update({'freightctl.source': 'c'*40}),
            lambda r, v, i: i[0]['Config']['Labels'].update({'freightctl.purpose': PRIVATE}),
            lambda r, v, i: v.update(Version='other'),
            lambda r, v, i: v['VulnerabilityDB'].update(Version=True),
            lambda r, v, i: v['VulnerabilityDB'].update(Version=1),
        ]
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                r, v, i = inputs()
                change(r, v, i)
                with self.assertRaises(gate.InvalidReport): self.check(r, v, i)

    def test_missing_or_invalid_inventory_never_qualifies_a_clean_scan(self):
        mutations = [
            lambda r: r.update(Results=[]),
            lambda r: r.update(Results=[{}]),
            lambda r: r['Results'][0].update(Packages=[]),
            lambda r: r['Results'][1].update(Packages=[]),
            lambda r: r['Results'][1]['Packages'][0].update(Version='6.3.1'),
            lambda r: r['Results'][0].update(Class='unknown'),
            lambda r: r['Results'][0].update(Type='unknown'),
            lambda r: r['Results'][0].update(Vulnerabilities='invalid'),
            lambda r: r['Results'][0].update(ExperimentalModifiedFindings={}),
            lambda r: r['Results'][0].update(Vulnerabilities=[{'Severity': 'NOT_A_SEVERITY', 'VulnerabilityID': PRIVATE}]),
        ]
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                r, v, i = inputs()
                change(r)
                with self.assertRaises(gate.InvalidReport): self.check(r, v, i)

    def test_stale_future_expired_missing_and_unzoned_times_fail(self):
        for key in ('UpdatedAt', 'DownloadedAt', 'NextUpdate'):
            for value in (None, '', PRIVATE, '2026-11-04T17:00:00', (NOW-timedelta(days=2)).isoformat()):
                with self.subTest(key=key, value=value):
                    r, v, i = inputs()
                    v['VulnerabilityDB'][key] = value
                    with self.assertRaises(gate.InvalidReport): self.check(r, v, i)
        for value in ((NOW+timedelta(hours=1)).isoformat(), (NOW-timedelta(hours=2)).isoformat()):
            r, v, i = inputs()
            r['CreatedAt'] = value
            with self.assertRaises(gate.InvalidReport): self.check(r, v, i)
        r, v, i = inputs()
        v['VulnerabilityDB']['UpdatedAt'] = (NOW+timedelta(hours=1)).isoformat()
        with self.assertRaises(gate.InvalidReport): self.check(r, v, i)

    def test_cli_exit_is_enforcing_and_failures_never_echo_input(self):
        with tempfile.TemporaryDirectory(prefix='freightctl-peer-summary-') as directory:
            root = Path(directory)
            r, v, i = inputs(datetime.now(timezone.utc))
            for name, value in (('report', r), ('version', v), ('image', i)):
                (root/name).write_text(json.dumps(value))
            for name in ('db', 'archive'):
                (root/name).write_bytes(b'synthetic bounded digest input')
            command = [sys.executable, str(HERE/'ci-peer-image-summary.py'), '--report', str(root/'report'),
                '--version', str(root/'version'), '--image', str(root/'image'), '--feed-database', str(root/'db'),
                '--archive', str(root/'archive'), '--commit', COMMIT, '--architecture', 'amd64']
            def run(expected, state):
                result = subprocess.run(command, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected)
                self.assertEqual(json.loads(result.stdout)['state'], state)
                self.assertNotIn(PRIVATE.encode(), result.stdout + result.stderr)
                self.assertEqual(result.stderr, b'')
            run(0, 'passed')
            r['Results'][0]['Vulnerabilities'] = [{'Severity': 'CRITICAL', 'VulnerabilityID': 'CVE-2026-12345'}]
            (root/'report').write_text(json.dumps(r))
            run(1, 'failed')
            for invalid in ('{"SchemaVersion":2,', '{"SchemaVersion":2,"SchemaVersion":2}', 'NaN', json.dumps(PRIVATE)):
                (root/'report').write_text(invalid)
                run(2, 'failed')
            (root/'report').write_bytes(b'x'*(32*1024*1024+1))
            run(2, 'failed')
            (root/'report').unlink()
            run(2, 'failed')


if __name__ == '__main__':
    os.umask(0o077)
    unittest.main()
