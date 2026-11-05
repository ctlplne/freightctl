#!/usr/bin/env python3
"""Trust/refusal contracts; --real also requires the pinned stock CI validator."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import core_bom_schema as gate

ROOT = Path(__file__).resolve().parents[1]
REAL = '--real' in sys.argv
if REAL:
    sys.argv.remove('--real')


class SchemaContracts(unittest.TestCase):
    def test_exact_licensed_schema_bundle_and_installer_hashes_are_required(self):
        pins, docs = gate.sources(ROOT)
        self.assertEqual(set(docs), set(gate.SCHEMAS))
        self.assertEqual({v['name'] for v in pins['packages']}, {'jsonschema', 'attrs', 'jsonschema-specifications',
            'referencing', 'rpds-py', 'typing-extensions'})
        with tempfile.TemporaryDirectory(prefix='freightctl-schema-contract-') as directory:
            root = Path(directory).resolve()
            (root/'scripts').mkdir()
            (root/'third_party').mkdir()
            shutil.copytree(ROOT/'third_party/cyclonedx-schema', root/'third_party/cyclonedx-schema')
            for name in ('bom-validator-pins.json', 'bom-validator-requirements.txt'):
                shutil.copyfile(ROOT/'scripts'/name, root/'scripts'/name)
            for name in ('scripts/bom-validator-pins.json', 'scripts/bom-validator-requirements.txt',
                    'third_party/cyclonedx-schema/bom-1.6.schema.json', 'third_party/cyclonedx-schema/LICENSE'):
                path = root/name; original = path.read_bytes(); path.write_bytes(original+b'changed')
                with self.assertRaises(ValueError):
                    gate.sources(root)
                path.write_bytes(original)
            (root/'third_party/cyclonedx-schema/foreign.schema.json').write_text('{}')
            with self.assertRaises(ValueError):
                gate.sources(root)

    def test_local_or_wrong_native_python_refuses_before_stock_validator_import(self):
        pins, _ = gate.sources(ROOT)
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), patch.object(gate.metadata, 'version') as version:
            with self.assertRaises(ValueError):
                gate.require_runtime(pins)
            version.assert_not_called()
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}), patch.object(gate.platform, 'system', return_value='Linux'), patch.object(gate.platform, 'machine', return_value='x86_64'), patch.object(gate.sys, 'version_info', (3, 11)), patch.object(gate.metadata, 'version') as version:
            with self.assertRaises(ValueError):
                gate.require_runtime(pins)
            version.assert_not_called()

    def test_exact_installed_versions_and_required_real_engine_controls(self):
        pins, _ = gate.sources(ROOT)
        versions = {v['name']:v['version'] for v in pins['packages']}
        with patch.dict(os.environ, {'GITHUB_ACTIONS':'true'}), patch.object(gate.platform, 'system', return_value='Linux'), patch.object(gate.platform, 'machine', return_value='aarch64'), patch.object(gate.sys, 'version_info', (3,12)), patch.object(gate.metadata, 'version', side_effect=lambda name: versions[name]):
            gate.require_runtime(pins)
            versions['jsonschema'] = '0.0.0'
            with self.assertRaises(ValueError):
                gate.require_runtime(pins)
        class PassingParser:
            def is_valid(self, _): return True
        with patch.object(gate, 'require_runtime'), patch.object(gate, 'engine', return_value=PassingParser()):
            with self.assertRaisesRegex(ValueError, '^'+gate.ERROR+'$'):
                gate.validate(ROOT, {'bomFormat':'CycloneDX', 'specVersion':'1.6'})

    def test_library_errors_never_expose_original_document_or_paths(self):
        with patch.object(gate, 'require_runtime'), patch.object(gate, 'engine', side_effect=RuntimeError('/private/credential-canary')):
            with self.assertRaisesRegex(ValueError, '^'+gate.ERROR+'$') as caught:
                gate.validate(ROOT, {'secret':'credential-canary'})
            self.assertNotIn('credential-canary', str(caught.exception))
        with self.assertRaises(ValueError):
            gate.load(b'{"duplicate":1,"duplicate":2}')


if REAL:
    class RealStockSchemaContracts(unittest.TestCase):
        def test_stock_schema_accepts_generated_core_bom_and_refuses_independent_shape_forgeries(self):
            pins, docs = gate.sources(ROOT)
            gate.require_runtime(pins)
            spec = importlib.util.spec_from_file_location('component_fixture', ROOT/'scripts/test-core-component-inventory.py')
            fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
            case = fixture.ComponentContracts('runTest'); case.setUp(); self.addCleanup(case.doCleanups)
            original = case.create()
            self.assertEqual(gate.validate(ROOT, original)['engine'], 'python-jsonschema')
            for change in (lambda v: v.update(bomFormat='invented'), lambda v: v['components'][0].update(type='invented'),
                    lambda v: v['metadata']['component']['hashes'][0].update(alg='invented'),
                    lambda v: v.update(unexpected='control'), lambda v: v['metadata']['tools'].update(components='invented')):
                value = copy.deepcopy(original); change(value)
                with self.assertRaisesRegex(ValueError, '^'+gate.ERROR+'$'):
                    gate.validate(ROOT, value)
            registry = gate.offline_registry(docs)
            # Unknown references cannot read a host file or make a network call.
            for uri in ('file:///private/credential-canary', 'https://outside.invalid/credential-canary'):
                with self.assertRaises(Exception):
                    registry.resolver().lookup(uri)


if __name__ == '__main__':
    unittest.main()
