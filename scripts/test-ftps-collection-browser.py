#!/usr/bin/env python3
"""Synthetic original-file refusal contracts; no Chrome, service or network."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import ftps_collection_browser as browser
import ftps_collection_metadata as metadata

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('collection_metadata_fixture', ROOT/'scripts/test-ftps-collection-metadata.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class BrowserEvidenceContracts(unittest.TestCase):
    def test_fixed_original_evidence_reason_does_not_emit_private_exception_fields(self):
        for message, code in browser.FAILURE_CODES.items():
            self.assertEqual(browser.failure_code(ValueError(message)), code)
            self.assertEqual(browser.failure_code(ValueError(message+' private-canary')), 'unrecognized-evidence')
        self.assertEqual(browser.failure_code(KeyError('private-canary')), 'missing-field')
        self.assertEqual(browser.failure_code(OSError('private-canary')), 'filesystem')

    def fixture(self, mode='explicit'):
        case = fixture.CollectionMetadataContracts('runTest')
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.fixture(mode)
        case.persist()
        self.case, self.private, self.mode = case, case.private, mode
        self.directory = self.private/('collection-browser-'+mode)
        (self.directory/'raw').mkdir(parents=True, mode=0o700)
        self.directory.chmod(0o700)
        values = case.values
        c, workflow, view, preview = (values[name] for name in
            ('connection-register', 'workflow-approve', 'collection-status', 'workflow-validate'))
        c, workflow = c['resource'], workflow['resource']
        config = {'root': str(ROOT), 'private': str(self.private), 'raw': str(self.directory/'raw'),
            'url': 'https://127.0.0.1:49152', 'certificate': str(self.private/'cert.pem'),
            'token': str(self.private/'owner.token'), 'tenant': 'tenant', 'partner': 'partner',
            'collections_only': True, 'collection_phase': 'ftps-metadata', 'source': c,
            'source_counter': str(case.directory/'source.json'), 'workflow': workflow, 'view': view}
        active = dict(case.inputs['source.json'], stopped=False)
        text = ' '.join((c['user']+'@'+c['address'], mode+' FTPS', c['ftps']['server_name'],
            c['ftps']['ca_sha256'], c['directory'], workflow['definition']['source']['manifest'], 'Local collection only'))
        result = {'kind': 'ftps-collection-browser-metadata-v1', 'state': 'passed', 'mode': mode,
            'workflow_preview': preview, 'view': view, 'preview_text': text, 'selected_text': text,
            'source_counter_before': active, 'source_counter_after': active, 'source_work_performed': False,
            'bytes_qualified': False, 'audits': list(browser.AUDITS), 'responses': [
                {'name': 'workflow-preview', 'method': 'POST', 'route': '/workflows/validate', 'status': 200,
                    'request': {'definition': workflow['definition']}},
                {'name': 'collection-view', 'method': 'GET', 'route': '/workflow-collections/'+view['job']['id'],
                    'status': 200, 'request': None}]}
        summary = {'state': 'passed', 'runtime_errors': [], 'external_egress': [],
            'model_started': False, 'production_activated': False, 'browser_version': '143.0.0.0', 'node_version': 'v26.0.0',
            'steps': [{'name': name+'-axe'} for name in browser.AUDITS]+[{'name': browser.STEP}]}
        self.files = {'config.json': config, 'raw/ftps-collection-browser-result.json': result,
            'raw/onboarding-exchange-browser.json': summary,
            'raw/workflow-preview.body': preview, 'raw/collection-view.body': view,
            **{'raw/'+name+'-axe.json': {'violations': [], 'passes': 5} for name in browser.AUDITS}}
        self.files = {k: copy.deepcopy(v) for k, v in self.files.items()}
        for name, value, request, method in (('workflow-preview', preview, {'definition': workflow['definition']}, 'POST'),
                ('collection-view', view, None, 'GET')):
            body = json.dumps(value).encode()
            for suffix, data in (('json', body), ('request', json.dumps(request).encode() if request is not None else b''),
                    ('headers', b'authorization: Bearer private-evidence-canary\ncontent-type: application/json\n')):
                metadata.private_write(self.directory/('raw/'+name+'.'+suffix), data)
            wire = {'name': name+'-wire-response', 'request_method': method, 'response_status': 200,
                'response_sha256': hashlib.sha256(body).hexdigest()}
            summary_steps = self.files['raw/onboarding-exchange-browser.json']['steps']
            summary_steps.insert(1 if name == 'workflow-preview' else 3, wire)
        path = self.directory/'raw/onboarding-exchange-review.png'
        path.write_bytes(b'\x89PNG\r\n\x1a\n'+bytes(100))
        path.chmod(0o600)
        name = 'cli-'+mode+'-collection-browser'
        for stream in ('stdout', 'stderr'):
            path = self.private/(name+'.'+stream)
            path.write_bytes(b'')
            path.chmod(0o600)
        self.steps = case.steps+[{'name': name, 'exit_code': 0,
            'stdout_sha256': hashlib.sha256(b'').hexdigest(), 'stderr_sha256': hashlib.sha256(b'').hexdigest()}]

    def persist(self):
        for name, value in self.files.items():
            path = self.directory/name
            path.write_text(json.dumps(value))
            path.chmod(0o600)
        return {str(p.relative_to(self.directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.directory.rglob('*') if p.is_file()}

    def check(self):
        return browser.validate(ROOT, self.private, self.mode, self.steps, self.persist())

    def test_both_mode_original_file_contracts_preserve_metadata_only_scope(self):
        for mode in ('explicit', 'implicit'):
            self.fixture(mode)
            result = self.check()
            self.assertEqual(result, {'state': 'passed', 'browser_phases': 1, 'accessibility_audits': 3,
                'source_contacts': 0, 'source_work_performed': False, 'bytes_qualified': False})
            self.assertNotIn('private-evidence-canary', json.dumps(result))

    def test_rehashed_changed_server_body_or_fixture_is_not_a_matching_browser_result(self):
        self.fixture()
        original = copy.deepcopy(self.files)
        for name, change in (
            ('raw/workflow-preview.body', lambda v: v.update(external_contact=True)),
            ('raw/collection-view.body', lambda v: v['job'].update(attempts=1)),
            ('config.json', lambda v: v.update(token='/private/other-token')),
            ('config.json', lambda v: v['source']['ftps'].update(server_name='other.invalid')),
            ('raw/ftps-collection-browser-result.json', lambda v: v.update(bytes_qualified=True)),
            ('raw/ftps-collection-browser-result.json', lambda v: v.update(source_work_performed=0)),
            ('raw/ftps-collection-browser-result.json', lambda v: v['source_counter_after'].update(accepted_connections=1))):
            self.files = copy.deepcopy(original)
            change(self.files[name])
            with self.assertRaises(ValueError):
                self.check()

    def test_actual_audits_process_and_runtime_cannot_be_replaced_by_a_pass_label(self):
        self.fixture()
        original = copy.deepcopy(self.files)
        for name, change in (
            ('raw/'+browser.AUDITS[0]+'-axe.json', lambda v: v.update(violations=[{'id': 'label'}])),
            ('raw/'+browser.AUDITS[1]+'-axe.json', lambda v: v.update(passes=True)),
            ('raw/onboarding-exchange-browser.json', lambda v: v.update(runtime_errors=['synthetic'])),
            ('raw/onboarding-exchange-browser.json', lambda v: v.update(external_egress=['https://outside.invalid'])),
            ('raw/onboarding-exchange-browser.json', lambda v: v.update(steps=[])),
            ('raw/onboarding-exchange-browser.json', lambda v: v.update(browser_version='not-observed'))):
            self.files = copy.deepcopy(original)
            change(self.files[name])
            with self.assertRaises(ValueError):
                self.check()
        self.files = original
        self.steps[-1]['exit_code'] = True
        with self.assertRaises(ValueError):
            self.check()

    def test_rendered_identity_and_credentials_are_checked_independently_from_hashes(self):
        self.fixture()
        original = copy.deepcopy(self.files)
        for value in ('explicit FTPS', 'private-evidence-canary', 'password_reference=/private/key',
                'Pinned source host SHA256:invented', str(self.private)):
            self.files = copy.deepcopy(original)
            self.files['raw/ftps-collection-browser-result.json']['selected_text'] = value
            with self.assertRaises(ValueError):
                self.check()

    def test_changed_hashes_linked_files_extra_files_or_private_modes_fail_closed(self):
        self.fixture()
        inventory = self.persist()
        path = self.directory/'raw/collection-view.body'
        path.write_text('{}')
        with self.assertRaises(ValueError):
            browser.validate(ROOT, self.private, self.mode, self.steps, inventory)
        inventory = self.persist()
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            browser.validate(ROOT, self.private, self.mode, self.steps, inventory)
        inventory = self.persist()
        extra = self.directory/'extra'
        extra.write_text('extra')
        with self.assertRaises(ValueError):
            browser.validate(ROOT, self.private, self.mode, self.steps, inventory)
        extra.unlink()
        path.unlink()
        path.symlink_to(self.private/'cert.pem')
        with self.assertRaises(ValueError):
            browser.validate(ROOT, self.private, self.mode, self.steps, inventory)

    def test_non_github_exercise_stops_before_creating_files_or_command(self):
        self.fixture()
        with patch.dict('os.environ', {}, clear=True), patch.object(browser, 'metadata', wraps=metadata):
            with self.assertRaises(ValueError):
                browser.exercise(ROOT, self.private, 'explicit', 49152, None, None, None, None,
                    [], lambda *_: self.fail('must not run command'), {}, {}, {}, None)

    def test_duplicate_or_nonfinite_original_http_fields_are_refused_even_when_rehashed(self):
        self.fixture()
        path = self.directory/'raw/workflow-preview.body'
        for raw in (b'{"external_contact":false,"external_contact":true}', b'{"value":NaN}', b'{"value":1.5}'):
            inventory = self.persist()
            path.write_bytes(raw)
            inventory['raw/workflow-preview.body'] = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):
                browser.validate(ROOT, self.private, self.mode, self.steps, inventory)


if __name__ == '__main__':
    unittest.main()
