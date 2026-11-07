#!/usr/bin/env python3
"""Synthetic original-output/refusal contracts; never start fixture services."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import ftps_collection_metadata as metadata


class CollectionMetadataContracts(unittest.TestCase):
    def test_fixed_evidence_classification_does_not_expose_exception_text(self):
        self.assertEqual(metadata.failure_code(ValueError('collection metadata command closure differs')), 'command-closure')
        self.assertEqual(metadata.failure_code(KeyError('private-canary')), 'missing-field')
        self.assertEqual(metadata.failure_code(OSError('private-canary')), 'filesystem')
        self.assertEqual(metadata.failure_code(ValueError('private-canary')), 'unrecognized-evidence')
        self.assertEqual(metadata.failure_code(RuntimeError('collection metadata command closure differs')), 'unrecognized-evidence')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='freightctl-collection-metadata-')
        self.addCleanup(self.temporary.cleanup)
        self.private = Path(self.temporary.name).resolve()
        self.mode = 'explicit'

    def fixture(self, mode='explicit'):
        self.mode = mode
        self.directory = self.private/('collection-metadata-'+mode)
        self.directory.mkdir(mode=0o700)
        self.prefix = 'cli-'+mode+'-collection-metadata-'
        write = lambda path, value: metadata.private_write(path, value)
        if not (self.private/'cert.pem').exists():
            write(self.private/'cert.pem', b'synthetic metadata CA; no TLS qualification')
            write(self.private/'owner.token', b'private-evidence-canary')
        write(self.directory/'source-password', b'private-evidence-canary')
        request = {'expected_version': 0, 'directory': '/source', 'ftps': {'destination': {
            'address': '127.0.0.1:49151', 'server_name': 'localhost', 'mode': mode, 'user': 'source',
            'ca_reference': str(self.private/'cert.pem'),
            'ca_sha256': hashlib.sha256((self.private/'cert.pem').read_bytes()).hexdigest(),
            'password_reference': str(self.directory/'source-password'),
            'password_sha256': hashlib.sha256((self.directory/'source-password').read_bytes()).hexdigest()},
            'staging_directory': '/private-stage', 'receiver_contract': {'schema_version': 1,
                'document_sha256': 'd'*64, 'staging_visibility': 'receiver-private', 'rename': 'may-replace',
                'duplicates': 'receiver-deduplicates-delivery-id', 'receipt': 'exact-readback'}}}
        c = metadata.dispatch.expected_connection_rotation({'id': '11111111-2222-4333-8444-555555555555'}, request, 1)
        definition = metadata.definition(c)
        fingerprint = hashlib.sha256(metadata.canonical(definition)).hexdigest()
        draft = {'id': '22222222-2222-4333-8444-555555555555', 'version': 1, 'definition': definition,
            'definition_hash': fingerprint, 'state': 'draft', 'revision': 1, 'approval_authority': 0}
        approved = dict(draft, state='approved', revision=2, approval_authority=3)
        d = {'schema_version': 1, 'workflow': metadata.ref(approved), 'source': definition['source'],
            'source_connection': c, 'source_identity': hashlib.sha256((c['id']+':'+c['directory']).encode()).hexdigest(),
            'authority_revision': 3, 'storage_id': '33333333-2222-4333-8444-555555555555',
            'namespace_root': '/', 'timeout_seconds': 120, 'effects': []}
        h = hashlib.sha256(metadata.canonical(d)).hexdigest()
        first = {'resource': {'kind': 'workflow_collection', 'id': '44444444-2222-4333-8444-555555555555',
            'definition_hash': h, 'state': 'queued', 'revision': 1}, 'replayed': False}
        job = {'id': first['resource']['id'], 'workflow_id': approved['id'], 'workflow_version': 1,
            'workflow_hash': fingerprint, 'definition': d, 'definition_hash': h, 'state': 'queued',
            'captured': False, 'revision': 1, 'fence': 0, 'attempts': 0, 'lease_owner': '', 'lease_until': None,
            'next_at': '2026-11-04T00:00:00Z', 'created_at': '2026-11-04T00:00:00Z',
            'deadline_at': '2026-11-04T00:02:00Z', 'manifest': None, 'manifest_hash': None, 'reason': 'awaiting_source'}
        view = {'job': job, 'inputs': [], 'local_states': [], 'business_acceptance': 'unknown',
            'current_authority': True, 'observed_state': 'queued'}
        cancelled = {'resource': dict(first['resource'], state='cancelled', revision=2), 'replayed': False}
        self.values = {'identity': {'tenant_id': 'tenant', 'partner_id': 'partner',
            'actor_id': '55555555-2222-4333-8444-555555555555', 'authority_revision': 3},
            'connection-register': {'resource': c, 'replayed': False},
            'connection-register-replay': {'resource': c, 'replayed': True},
            'workflow-validate': {'definition': definition, 'definition_hash': fingerprint, 'effects': [],
                'external_contact': False, 'approval_required': True,
                'collection': {'kind': 'ftps.collect', 'connection': c, 'source': definition['source']}},
            'workflow-draft': {'resource': draft, 'replayed': False},
            'workflow-approve': {'resource': approved, 'replayed': False},
            'collection-preview': {'definition': d, 'definition_hash': h, 'external_contact': False, 'approval_required': True},
            'collection-start': first, 'collection-start-replay': dict(first, replayed=True),
            'collection-status': view, 'collection-cancel': cancelled,
            'collection-cancel-replay': dict(cancelled, replayed=True),
            'connection-revoke': {'resource': dict(c, state='revoked', revision=2), 'replayed': False},
            'collection-final-status': dict(view, job=dict(job, state='cancelled', revision=2, reason='operator_cancelled'),
                current_authority=False, observed_state='cancelled')}
        # Each original output is separate, like independent process/HTTP reads.
        self.values = copy.deepcopy(self.values)
        self.values = {k: copy.deepcopy(v) for k, v in self.values.items()}
        selection = {'workflow': metadata.ref(approved), 'timeout_seconds': 120, 'expected_authority_revision': 3}
        self.inputs = {'connection.json': request, 'workflow-preview.json': {'definition': definition},
            'workflow.json': {'expected_version': 0, 'definition': definition}, 'selection.json': selection,
            'start.json': {'selection': selection, 'definition_hash': h},
            'cancel.json': {'definition_hash': h, 'expected_revision': 1},
            'source.json': {'schema_version': 1, 'kind': metadata.dispatch.SPY_KIND, 'accepted_connections': 0,
                'stopped': True, 'budget_exhausted': False},
            'collection-api-replay.body': dict(first, replayed=True),
            'collection-api-history-replay.body': dict(first, replayed=True)}
        write(self.directory/'owner.headers', b'Authorization: Bearer private-evidence-canary\nIdempotency-Key: '
            +(self.prefix+'start').encode()+b'\nContent-Type: application/json\n')

    def persist(self):
        self.steps = []
        for name in metadata.COMMANDS:
            raw = b'200' if 'api-' in name else json.dumps(self.values[name]).encode()
            for stream, value in [('stdout', raw), ('stderr', b'')]:
                path = self.private/(self.prefix+name+'.'+stream)
                path.write_bytes(value)
                path.chmod(0o600)
            self.steps.append({'name': self.prefix+name, 'exit_code': 0,
                'stdout_sha256': hashlib.sha256(raw).hexdigest(), 'stderr_sha256': hashlib.sha256(b'').hexdigest()})
        for name, value in self.inputs.items():
            path = self.directory/name
            path.write_text(json.dumps(value))
            path.chmod(0o600)
        self.inventory = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.directory.iterdir() if p.is_file()}

    def validate(self):
        self.persist()
        return metadata.validate(self.private, self.mode, self.steps, self.inventory)

    def test_both_modes_keep_exact_original_results_without_claiming_bytes_or_browser(self):
        for mode in ('explicit', 'implicit'):
            self.fixture(mode)
            result = self.validate()
            self.assertEqual(result['commands'], 16)
            self.assertEqual(result['saved_key_replays'], 5)
            self.assertEqual(result['source_contacts'], 0)
            self.assertFalse(result['bytes_qualified'])
            self.assertFalse(result['browser_qualified'])
            self.assertNotIn('private-evidence-canary', json.dumps(result))
            self.assertNotIn(str(self.private), json.dumps(result))

    def test_reordered_jsonb_receipts_keep_the_original_typed_definition_hash(self):
        def reorder(value):
            if type(value) is dict:
                return {key: reorder(value[key]) for key in reversed(value)}
            if type(value) is list:
                return [reorder(item) for item in value]
            return value
        for mode in ('explicit', 'implicit'):
            self.fixture(mode)
            original_hash = self.values['collection-preview']['definition_hash']
            self.values = reorder(self.values)
            self.inputs = reorder(self.inputs)
            result = self.validate()
            self.assertEqual(self.values['collection-preview']['definition_hash'], original_hash)
            self.assertEqual(result['state'], 'passed')
            self.assertEqual(result['commands'], 16)
            self.assertEqual(result['saved_key_replays'], 5)
            self.assertEqual(result['source_contacts'], 0)
            self.assertFalse(result['bytes_qualified'])
            self.assertFalse(result['browser_qualified'])

    def test_rehashed_detached_source_and_unknown_effect_authority_are_refused(self):
        self.fixture()
        original = copy.deepcopy(self.values)
        for mutate in (lambda d: d['source'].update(kind='sftp.collect'),
                       lambda d: d['source_connection'].update(user='other'),
                       lambda d: d.update(effects=[{'recipient': 'invented'}]),
                       lambda d: d.update(schedule={'authority': 'invented'}),
                       lambda d: d.update(authority_revision=True)):
            self.values = copy.deepcopy(original)
            d = self.values['collection-preview']['definition']
            mutate(d)
            self.values['collection-preview']['definition_hash'] = hashlib.sha256(metadata.canonical(d)).hexdigest()
            with self.assertRaises(ValueError):
                self.validate()

    def test_freshly_hashed_original_output_cannot_invent_acquisition_or_receipt_recovery(self):
        self.fixture()
        original = copy.deepcopy(self.values)
        changes = [('collection-start-replay', lambda v: v.update(replayed=False)),
            ('collection-start', lambda v: v['resource'].update(execution_authority=True)),
            ('collection-final-status', lambda v: v['job'].update(attempts=1)),
            ('collection-final-status', lambda v: v['job'].update(fence=False)),
            ('collection-final-status', lambda v: v['job'].update(captured=True)),
            ('collection-final-status', lambda v: v.update(business_acceptance='accepted')),
            ('collection-cancel', lambda v: v['resource'].update(revision=3)),
            ('connection-revoke', lambda v: v['resource'].update(state='active'))]
        for name, change in changes:
            self.values = copy.deepcopy(original)
            change(self.values[name])
            with self.assertRaises(ValueError):
                self.validate()

    def test_original_request_and_https_key_or_body_changes_are_refused(self):
        self.fixture()
        original = copy.deepcopy(self.inputs)
        for name, change in [('start.json', lambda v: v['selection'].update(timeout_seconds=3600)),
                ('workflow.json', lambda v: v['definition']['source'].update(max_files=64)),
                ('collection-api-history-replay.body', lambda v: v['resource'].update(state='cancelled')),
                ('source.json', lambda v: v.update(accepted_connections=1)),
                ('source.json', lambda v: v.update(stopped=False))]:
            self.inputs = copy.deepcopy(original)
            change(self.inputs[name])
            with self.assertRaises(ValueError):
                self.validate()

    def test_nonzero_private_stderr_duplicates_and_changed_original_hashes_fail_closed(self):
        self.fixture()
        self.persist()
        self.steps[0]['exit_code'] = True
        with self.assertRaises(ValueError):
            metadata.validate(self.private, self.mode, self.steps, self.inventory)
        self.persist()
        path = self.private/(self.prefix+'identity.stderr')
        path.write_bytes(b'private-evidence-canary')
        self.steps[0]['stderr_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'command failed or changed'):
            metadata.validate(self.private, self.mode, self.steps, self.inventory)
        self.persist()
        path = self.private/(self.prefix+'identity.stdout')
        path.write_bytes(b'{"authority_revision":1,"authority_revision":3}')
        self.steps[0]['stdout_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'duplicate evidence key'):
            metadata.validate(self.private, self.mode, self.steps, self.inventory)

    def test_no_subprocess_or_socket_is_started_outside_disposable_github(self):
        command = Mock()
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), patch.object(metadata.dispatch, 'ContactSpy') as spy:
            with self.assertRaisesRegex(ValueError, 'disposable GitHub'):
                metadata.exercise(self.private, self.private, 'explicit', 1, self.private/'cert',
                    self.private/'binary', 'tenant', 'partner', self.private/'token', [], command)
            command.assert_not_called()
            spy.assert_not_called()

    def test_registration_failure_closes_owned_spy_and_never_places_credentials_in_arguments(self):
        certificate = self.private/'cert.pem'
        owner = self.private/'owner.token'
        metadata.private_write(certificate, b'synthetic public CA, no TLS claim')
        metadata.private_write(owner, b'private-owner-canary')
        spy = Mock()
        spy.port = 49151
        calls = []
        directory = self.private/'collection-metadata-explicit'
        def command(name, argv, timeout):
            calls.append(name)
            self.assertEqual(timeout, 20)
            self.assertEqual(argv[argv.index('--token-file')+1], owner)
            self.assertNotIn('private-owner-canary', str(argv))
            if argv[1] == 'identity':
                return b'{"actor_id":"55555555-2222-4333-8444-555555555555","authority_revision":3}'
            self.assertEqual(argv[1], 'connection-register')
            path = argv[argv.index('--request-file')+1]
            self.assertEqual(path, directory/'connection.json')
            request = metadata.load(path)
            destination = request['ftps']['destination']
            password = directory/'source-password'
            self.assertEqual(destination['password_reference'], str(password))
            self.assertEqual(destination['password_sha256'], hashlib.sha256(password.read_bytes()).hexdigest())
            self.assertEqual(destination['ca_reference'], str(certificate))
            self.assertEqual(destination['ca_sha256'], hashlib.sha256(certificate.read_bytes()).hexdigest())
            self.assertEqual(destination['address'], '127.0.0.1:49151')
            self.assertEqual(destination['mode'], 'explicit')
            self.assertNotIn(password.read_text(), str(argv))
            self.assertEqual(password.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            raise RuntimeError('synthetic-registration-failure')
        mask = os.umask(0o022)
        try:
            with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_WORKSPACE': str(self.private)}), \
                 patch.object(metadata.platform, 'system', return_value='Linux'), \
                 patch.object(metadata.dispatch, 'ContactSpy', return_value=spy) as create_spy:
                with self.assertRaisesRegex(RuntimeError, '^synthetic-registration-failure$'):
                    metadata.exercise(self.private, self.private, 'explicit', 1, certificate,
                        self.private/'binary', 'tenant', 'partner', owner, [], command)
                create_spy.assert_called_once_with(directory/'source.json')
        finally:
            os.umask(mask)
        spy.stop.assert_called_once_with()
        self.assertEqual(calls, ['cli-explicit-collection-metadata-identity',
            'cli-explicit-collection-metadata-connection-register'])
        self.assertEqual(owner.read_bytes(), b'private-owner-canary')

    def test_private_input_creation_is_explicit_and_cannot_overwrite_original(self):
        path = self.private/'private-input'
        mask = os.umask(0o022)
        try:
            metadata.private_write(path, b'original')
        finally:
            os.umask(mask)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            metadata.private_write(path, b'replacement')
        self.assertEqual(path.read_bytes(), b'original')


if __name__ == '__main__':
    unittest.main()
