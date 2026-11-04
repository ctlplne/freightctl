#!/usr/bin/env python3
"""Run the real fixture producer with process/HTTP/Page stand-ins only."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ftps_collection_metadata as metadata
import ftps_collection_operator as operator

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((ROOT/'web/tests/fixtures/ftps-collections.json').read_text())


class OperatorContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='freightctl-operator-contract-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root/'.private').mkdir(mode=0o700)
        self.private = self.root/'.private'/('ftps-'+'a'*32)
        self.private.mkdir(mode=0o700)
        for name, value in (('cert.pem', b'synthetic CA'), ('owner.token', b'owner-private-canary'), ('key.pem', b'synthetic key')):
            metadata.private_write(self.private/name, value)
        self.steps, self.argv, self.stops, self.counts = [], [], [], {}
        # The real parent generates estate and database IDs independently.
        self.database = 'freightctl_ftps_'+'b'*32
        metadata.private_write(self.private/'pg-runtime.dsn',
            ('postgresql://runtime:private-stand-in@127.0.0.1:25432/'+self.database+'?sslmode=disable').encode())
        self.fail_browser = False
        self.consumer = {'tenant_id': '10000000-1111-4111-8111-111111111111',
            'partner_id': '10000001-1111-4111-8111-111111111111',
            'actor_id': '10000002-1111-4111-8111-111111111111', 'authority_revision': 3}
        self.producer = dict(self.consumer, tenant_id='20000000-1111-4111-8111-111111111111',
            partner_id='20000001-1111-4111-8111-111111111111', actor_id='20000002-1111-4111-8111-111111111111')
        case = self

        class FakeSource:
            def __init__(self, root, private, mode, database, steps, bounded_output):
                self.mode, self.private, self.steps = mode, private, steps
                self.database = database
                self.directory = private/('source-helper-'+mode)
                self.label = 'cli-'+mode+'-collection-source'
                self.closed = False
                case.counts[mode] = 0

            def value(self, stopped=False):
                return {'schema_version': 1, 'kind': 'freightctl-ftps-source-witness-v1', 'mode': self.mode,
                    'port': 49151, 'accepted_connections': case.counts[self.mode], 'budget_exhausted': False, 'stopped': stopped}

            def save(self, stopped=False):
                path = self.directory/'counter.json'
                path.write_bytes(metadata.canonical(self.value(stopped)))
                path.chmod(0o600)
                return self.value(stopped)

            def start(self):
                self.directory.mkdir(mode=0o700)
                metadata.private_write(self.directory/'config.json', metadata.canonical({'database': self.database,
                    'dsn_file': str(self.private/'pg-runtime.dsn'), 'storage': str(self.private/'custody'),
                    'certificate': str(self.private/'cert.pem'), 'key': str(self.private/'key.pem'), 'mode': self.mode}))
                return self.save()

            def snapshot(self):
                return self.save()

            def stop(self):
                case.stops.append(self.mode)
                if self.closed:
                    raise AssertionError('owned source stopped twice')
                self.closed = True
                case.output(self.label, b'')
                return self.save(True)

        self.fake_source = FakeSource

    def output(self, name, data, code=0):
        step = {'name': name, 'exit_code': code}
        for stream, content in (('stdout', data), ('stderr', b'')):
            metadata.private_write(self.private/(name+'.'+stream), content)
            step[stream+'_sha256'] = hashlib.sha256(content).hexdigest()
        self.steps.append(step)
        return data

    def entry(self, mode, name):
        return {'id': '30000000-1111-4111-8111-111111111111', 'path': '/'+name, 'parent': '/', 'kind': 'file',
            'file_id': ('30000001' if name == 'source.csv' else '30000002')+'-1111-4111-8111-111111111111',
            'owner_actor_id': self.producer['actor_id'], 'mode': 384, 'revision': 1, 'deleted': False,
            'size_bytes': len((self.private/('collection-operator-'+mode)/name).read_bytes())}

    def browser(self, mode, config_path):
        config = metadata.load(config_path)
        directory, raw = config_path.parent, config_path.parent/'raw'
        fixture = copy.deepcopy(FIXTURES['explicit-local'])
        d, c = config['definition'], config['source']
        draft = dict(fixture['workflow'], version=1, revision=1, state='draft', approval_authority=0,
            definition=d, definition_hash=config['definition_hash'])
        approved = dict(draft, revision=2, state='approved', approval_authority=3)
        preview = {'definition': d, 'definition_hash': config['definition_hash'], 'effects': [],
            'collection': {'kind': 'ftps.collect', 'source': d['source'], 'connection': c}, 'external_contact': False, 'approval_required': True}
        definition = {'schema_version': 1, 'workflow': metadata.ref(approved), 'source': d['source'], 'source_connection': c,
            'source_identity': hashlib.sha256((c['id']+':/').encode()).hexdigest(), 'authority_revision': 3,
            'storage_id': '40000000-1111-4111-8111-111111111111', 'namespace_root': '/', 'timeout_seconds': 300, 'effects': []}
        fingerprint = hashlib.sha256(metadata.canonical(definition)).hexdigest()
        p = {'definition': definition, 'definition_hash': fingerprint, 'external_contact': False, 'approval_required': True}
        view = fixture['view']
        view['job'].update(definition=definition, definition_hash=fingerprint, workflow_id=draft['id'], workflow_version=1,
            workflow_hash=config['definition_hash'], manifest=config['manifest'], manifest_hash=config['manifest_hash'])
        item = view['inputs'][0]
        item.update(source_name='source.csv', size_bytes=len(operator.payload(mode)), sha256=config['manifest']['files'][0]['sha256'],
            target_path='/'+config['manifest']['files'][0]['sha256']+'-source.csv')
        view['local_states'] = [{'input_id': item['id'], 'state': 'published'}]
        initial = dict(view, job=dict(view['job'], state='queued', captured=False, attempts=0, fence=0, manifest=None, manifest_hash=None),
            observed_state='queued', inputs=[], local_states=[])
        queued = {'kind': 'workflow_collection', 'id': view['job']['id'], 'definition_hash': fingerprint, 'state': 'queued', 'revision': 1}
        worked = dict(queued, state='captured', revision=view['job']['revision'])
        selection = {'workflow': metadata.ref(approved), 'timeout_seconds': 300, 'expected_authority_revision': 3}
        reads = [
            {'name': 'workflow-preview', 'route': '/workflows/validate', 'method': 'POST', 'status': 200, 'request': {'definition': d}},
            {'name': 'job-preview', 'route': '/workflow-collections/preview', 'method': 'POST', 'status': 200, 'request': selection},
            *({'name': name, 'route': '/workflow-collections/'+queued['id'], 'method': 'GET', 'status': 200, 'request': None}
                for name in ('queued-view', 'captured-view'))]
        read_steps = {}
        for observed, value in zip(reads, (preview, p, initial, view)):
            name = observed['name']
            body = metadata.canonical(value)
            for suffix, data in (('body', body), ('json', body), ('request', metadata.canonical(observed['request']) if observed['request'] is not None else b''),
                    ('headers', b'authorization: Bearer owner-private-canary\ncontent-type: application/json\n')):
                metadata.private_write(raw/(name+'.'+suffix), data)
            read_steps[name] = {'name': name+'-wire-response', 'request_method': observed['method'], 'response_status': 200,
                'response_sha256': hashlib.sha256(body).hexdigest()}
        responses, records = [], [{'name': 'ftps-operator-form-axe'}, read_steps['workflow-preview']]
        for index, (name, route, request, resource) in enumerate(zip(operator.DECISIONS,
                ('/workflows/drafts', '/workflows/'+draft['id']+'/1/approve', '/workflow-collections', '/workflow-collections/'+queued['id']+'/work'),
                ({'expected_version': 0, 'definition': d}, {'definition_hash': draft['definition_hash'], 'expected_revision': 1},
                    {'selection': selection, 'definition_hash': fingerprint}, {'definition_hash': fingerprint}), (draft, approved, queued, worked))):
            if index == 2:
                records.append(read_steps['job-preview'])
            if index == 3:
                records.append(read_steps['queued-view'])
            records.append({'name': operator.AUDITS[index+1]+'-axe'})
            observed = []
            for attempt in (0, 1):
                label = 'ftps-operator-'+name+'-'+str(attempt)
                key = 'saved-key-'+name
                body = metadata.canonical({'resource': resource, 'replayed': bool(attempt)})
                metadata.private_write(raw/(label+'.json'), body)
                metadata.private_write(raw/(label+'.request'), metadata.canonical(request))
                metadata.private_write(raw/(label+'.headers'), ('authorization: Bearer owner-private-canary\ncontent-type: application/json\nidempotency-key: '+key+'\n').encode())
                observed.append({'status': 200, 'body': body.decode(), 'selection': request, 'idempotency_key': key})
                records.append({'name': label+'-wire-response', 'request_method': 'POST', 'response_status': 200,
                    'response_sha256': hashlib.sha256(body).hexdigest()})
            records.append({'name': 'ftps-operator-'+name+'-original-key-recovery'})
            responses.append({'route': route, 'label': 'ftps-operator-'+name, 'observed': observed})
        records.extend([read_steps['captured-view'], {'name': 'ftps-operator-captured-axe'}])
        counter = lambda count: {'schema_version': 1, 'kind': 'freightctl-ftps-source-witness-v1', 'mode': mode,
            'port': 49151, 'accepted_connections': count, 'budget_exhausted': False, 'stopped': False}
        result = {'kind': 'ftps-collection-operator-v1', 'state': 'passed', 'mode': mode, 'preview': preview,
            'draft': draft, 'approved': approved, 'job_preview': p, 'queued': queued, 'worked': worked, 'view': view,
            'visible': ' '.join((c['user']+'@'+c['address'], mode+' FTPS', c['ftps']['server_name'], c['ftps']['ca_sha256'],
                'Local collection only', item['file_id'])), 'counters': [counter(n) for n in (2, 2, 3)], 'responses': responses,
            'reads': reads, 'audits': list(operator.AUDITS), 'source_control_connections': 1, 'original_key_replays': 4, 'business_acceptance': 'unknown'}
        metadata.private_write(raw/'ftps-operator-result.json', metadata.canonical(result))
        metadata.private_write(raw/'onboarding-exchange-browser.json', metadata.canonical({'state': 'passed', 'steps': records,
            'runtime_errors': [], 'external_egress': [], 'model_started': False, 'production_activated': False,
            'browser_version': '156.0.0.0', 'node_version': 'v26.0.0'}))
        for name in operator.AUDITS:
            metadata.private_write(raw/(name+'-axe.json'), b'{"violations":[],"passes":5}')
        metadata.private_write(raw/'onboarding-exchange-review.png', b'\x89PNG\r\n\x1a\n'+bytes(100))
        self.counts[mode] += 1
        return view

    def command(self, name, argv, timeout):
        self.argv.append(list(map(str, argv)))
        require = self.assertTrue
        require(not any('owner-private-canary' in str(v) or 'producer-private-canary' in str(v) for v in argv))
        if name == 'collection-source-build':
            metadata.private_write(self.private/'source-ftps', b'synthetic helper, never executed')
            return self.output(name, b'')
        match = __import__('re').fullmatch('cli-(explicit|implicit)-collection-operator-(.+)', name)
        mode, suffix = match.groups()
        directory = self.private/('collection-operator-'+mode)
        result = b''
        if suffix == 'producer-token':
            metadata.private_write(directory/'producer.token', b'producer-private-canary')
        elif suffix == 'producer-enroll':
            self.producer['tenant_id'] = argv[argv.index('--tenant')+1]
            self.producer['partner_id'] = argv[argv.index('--partner')+1]
        elif suffix in ('identity', 'producer-identity'):
            result = metadata.canonical(self.consumer if suffix == 'identity' else self.producer)
        elif suffix.startswith('upload-'):
            self.counts[mode] += 1
        elif suffix.startswith(('source-', 'ready-')) and suffix.endswith(('before', 'after')):
            result = metadata.canonical(self.entry(mode, 'source.csv' if suffix.startswith('source-') else 'operator.ready.json'))
        elif suffix.startswith('connection-register'):
            c = metadata.dispatch.expected_connection_rotation({'id': '50000000-1111-4111-8111-111111111111'}, metadata.load(directory/'connection.json'), 1)
            result = metadata.canonical({'resource': c, 'replayed': suffix.endswith('replay')})
        elif suffix == 'browser':
            if self.fail_browser:
                self.output(name, b'', 1)
                raise RuntimeError('first browser failure preserved')
            self.views[mode] = self.browser(mode, Path(argv[-1]))
        elif suffix == 'status':
            result = metadata.canonical(self.views[mode])
        elif suffix.endswith('readback'):
            target = Path(argv[argv.index('--output')+1])
            metadata.private_write(target, (directory/('operator.ready.json' if suffix == 'ready-readback' else 'source.csv')).read_bytes())
            result = b'200'
        else:
            self.fail('unexpected command '+suffix)
        return self.output(name, result)

    def run_fixture(self, mode='explicit'):
        self.views = getattr(self, 'views', {})
        with patch.object(metadata, 'require_environment'), patch.object(operator.source, 'Source', self.fake_source):
            return operator.exercise(self.root, self.private, mode, self.database, 49152,
                self.private/'cert.pem', self.private/'freightctl', self.consumer['tenant_id'], self.consumer['partner_id'],
                self.private/'owner.token', self.steps, self.command, lambda: None)

    def check(self, mode='explicit'):
        return operator.validate(self.root, self.private, mode, self.steps, operator.inventory(self.private, mode), self.database)

    def change(self, path, mutate):
        value = metadata.load(path)
        mutate(value)
        path.write_bytes(metadata.canonical(value))

    def test_real_producer_with_stand_ins_closes_each_source_once_and_keeps_private_files(self):
        previous = os.umask(0o022)
        try:
            for mode in ('explicit', 'implicit'):
                checked, inventory = self.run_fixture(mode)
                self.assertEqual(checked['captured_files'], 1)
                self.assertEqual(checked['source_kind'], 'native-freightctl')
                self.assertEqual(checked['business_acceptance'], 'unknown')
                self.assertEqual(set(inventory['operator']), operator.FILES)
                self.assertEqual(self.counts[mode], 3)
            self.assertEqual(self.stops, ['explicit', 'implicit'])
            self.assertEqual(sum(step['name'] == 'collection-source-build' for step in self.steps), 1)
        finally:
            os.umask(previous)

    def test_original_browser_failure_survives_exact_source_cleanup(self):
        self.fail_browser = True
        with self.assertRaisesRegex(RuntimeError, 'first browser failure preserved'):
            self.run_fixture()
        self.assertEqual(self.stops, ['explicit'])
        self.assertTrue(metadata.load(self.private/'source-helper-explicit/counter.json')['stopped'])

    def test_rehashed_server_forgeries_and_claims_cannot_replace_original_artifacts(self):
        self.run_fixture()
        path = self.private/'collection-operator-explicit/raw/ftps-operator-result.json'
        original = path.read_bytes()
        for mutation in (lambda v: v.update(original_key_replays=True), lambda v: v.update(source_control_connections=0),
                lambda v: v['view']['job'].update(attempts=2), lambda v: v['view']['inputs'][0].update(file_id=None),
                lambda v: v['counters'][1].update(accepted_connections=3), lambda v: v['counters'][2].update(accepted_connections=True),
                lambda v: v['responses'][3]['observed'][1].update(idempotency_key='changed-key'),
                lambda v: v['reads'][1]['request'].update(timeout_seconds=600), lambda v: v.update(visible='owner-private-canary')):
            path.write_bytes(original)
            self.change(path, mutation)
            with self.assertRaises(ValueError):
                self.check()
        path.write_bytes(original)
        self.assertEqual(self.check()['state'], 'passed')

    def test_rehashed_bytes_source_revision_saved_headers_and_private_permissions_are_required(self):
        self.run_fixture()
        directory = self.private/'collection-operator-explicit'
        for relative in ('consumer.body', 'producer.body', 'ready.body', 'raw/ftps-operator-work-1.headers', 'raw/ftps-operator-draft-0.request'):
            path = directory/relative
            original = path.read_bytes()
            path.write_bytes(b'{}')
            with self.assertRaises(ValueError):
                self.check()
            path.write_bytes(original)
        path = directory/'producer.token'
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.check()
        path.chmod(0o600)
        (directory/'extra.json').write_text('{}')
        with self.assertRaises(ValueError):
            self.check()

    def test_source_cleanup_and_first_artifact_hashes_cannot_be_forged(self):
        _, inventory = self.run_fixture()
        path = self.private/'source-helper-explicit/counter.json'
        self.change(path, lambda v: v.update(stopped=False))
        with self.assertRaises(ValueError):
            self.check()
        self.change(path, lambda v: v.update(stopped=True))
        (self.private/'collection-operator-explicit/consumer.body').write_bytes(b'wrong')
        with self.assertRaisesRegex(ValueError, 'original evidence changed'):
            operator.validate(self.root, self.private, 'explicit', self.steps, inventory, self.database)

    def test_parent_database_and_protected_runtime_reference_must_agree_without_deriving_from_directory_uuid(self):
        self.run_fixture()
        self.assertNotEqual(self.private.name.removeprefix('ftps-'), self.database.removeprefix('freightctl_ftps_'))
        self.assertEqual(self.check()['state'], 'passed')
        path = self.private/'pg-runtime.dsn'
        original = path.read_bytes()
        for dsn in (b'postgresql://runtime@127.0.0.1:25432/freightctl',
                ('postgresql://runtime@127.0.0.1:25432/freightctl_ftps_'+'a'*32).encode(),
                ('postgresql://runtime@remote.invalid:25432/'+self.database).encode()):
            path.write_bytes(dsn)
            with self.assertRaises(ValueError):
                self.check()
        path.write_bytes(original)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.check()
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            operator.validate(self.root, self.private, 'explicit', self.steps, operator.inventory(self.private, 'explicit'), None)
        path.unlink()
        with self.assertRaises(ValueError):
            self.check()

    def test_fixed_diagnostics_refuse_secret_fields_unknown_stages_and_boolean_lines(self):
        value = {'kind': 'ftps-operator-browser-failure', 'mode': 'implicit', 'stage': 'operator-work',
            'error_kind': 'assertion', 'source_file': 'driver', 'source_line': 200}
        self.assertEqual(operator.safe_observation(value), value)
        for changed in (dict(value, secret='private-canary'), dict(value, source_line=True), dict(value, stage='private-canary'),
                dict(value, error_kind='constructor'), dict(value, source_file='/private/canary')):
            self.assertIsNone(operator.safe_observation(changed))
        self.assertIsNone(operator.command_suffix('cli-explicit-collection-operator-private-canary'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
