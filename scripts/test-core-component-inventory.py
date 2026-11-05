#!/usr/bin/env python3
"""Original-file and forged inventory contracts; no compiler, npm or network."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import core_component_inventory as inventory

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('repro_fixture', HERE/'test-repro-builds.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class ComponentContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='freightctl-component-contract-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        fixture.archive(self.root/'source.tar')
        self.source = self.root/'source'
        fixture.runner.extract(self.root/'source.tar', self.source)
        self.binary = self.root/'binary'
        self.binary.write_bytes(fixture.BINARY)
        self.info = fixture.build_info()

    def create(self, standard_library=None):
        return inventory.create(self.source, fixture.runner.sources(self.source), self.info,
            fixture.COMMIT, 'amd64', self.binary, hashlib.sha256(self.binary.read_bytes()).hexdigest(), standard_library)

    def standard_library(self):
        root = self.root/'toolchain'; root.mkdir()
        packages = fixture.package_fixture.fixture(root, self.info)
        return fixture.runner.go_packages.capture(fixture.package_fixture.raw(packages), root, self.info)

    def test_standard_library_source_manifest_properties_and_native_import_edges_are_bound(self):
        selected = self.standard_library(); result = self.create(selected)
        libraries = {v['name']:v for v in result['components'] if any(p['name'] == 'freightctl:ecosystem'
            and p['value'] == 'go-toolchain-package' for p in v.get('properties', []))}
        self.assertEqual(set(libraries), {'go/fmt', 'go/unsafe', 'go/vendor/example.test/leaf'})
        self.assertTrue(all(v['version'] == 'go1.26.10' and 'hashes' not in v for v in libraries.values()))
        self.assertEqual(next(v['dependsOn'] for v in result['dependencies'] if v['ref'] == libraries['go/fmt']['bom-ref']),
            sorted(libraries[v]['bom-ref'] for v in ('go/unsafe','go/vendor/example.test/leaf')))
        properties = {v['name']:v['value'] for v in result['metadata']['component']['properties']}
        self.assertEqual(properties['freightctl:go-package-graph-sha256'], selected['package_graph_sha256'])

    def mutate(self, name, change):
        path = self.source/name
        value = json.loads(path.read_bytes())
        change(value)
        path.write_bytes(inventory.encoded(value))

    def rebind_manifest(self, name):
        self.mutate('internal/browser/assets/manifest.json', lambda v: next(x for x in v['sources']
            if x['path'] == name).update(sha256=hashlib.sha256((self.source/name).read_bytes()).hexdigest()))

    def test_exact_core_identity_go_directory_hashes_and_locked_npm_integrity_have_distinct_meanings(self):
        result = self.create()
        self.assertEqual((result['bomFormat'], result['specVersion']), ('CycloneDX', '1.6'))
        root = result['metadata']['component']
        self.assertEqual(root['hashes'], [{'alg': 'SHA-256', 'content': hashlib.sha256(fixture.BINARY).hexdigest()}])
        self.assertEqual({(v['type'], v['name']) for v in result['components']}, {
            ('file','browser/index.html'), ('library','example'), ('library','github.com/jackc/pgx/v5'),
            ('library','github.com/ProtonMail/go-crypto'), ('library','github.com/fclairamb/ftpserverlib')})
        modules = [v for v in result['components'] if v['name'].startswith('github.com/')]
        self.assertTrue(all('hashes' not in v for v in modules)) # Go h1 is not an archive checksum.
        npm = next(v for v in result['components'] if v['name'] == 'example')
        self.assertEqual(npm['hashes'], [{'alg': 'SHA-512', 'content': '00'*64}])
        self.assertEqual(set(result['dependencies'][0]['dependsOn']), {v['bom-ref'] for v in result['components']})
        self.assertNotIn(str(self.root), inventory.encoded(result).decode())
        self.assertNotIn('licenses', inventory.encoded(result).decode())
        self.assertEqual(inventory.encoded(self.create()), inventory.encoded(result))

    def test_source_assets_must_match_manifest_and_exist_as_exact_final_binary_bytes(self):
        for name in ('internal/browser/assets/index.html', 'web/package-lock.json'):
            path = self.source/name
            original = path.read_bytes(); path.write_bytes(original+b'changed')
            with self.assertRaises(ValueError):
                self.create()
            path.write_bytes(original)
        self.binary.write_bytes(fixture.BINARY.replace(b'qualification fixture', b'changed bytes'))
        with self.assertRaises(ValueError):
            self.create()
        self.binary.write_bytes(fixture.BINARY)
        (self.source/'internal/browser/assets/extra.js').write_text('unlisted embedded code')
        with self.assertRaises(ValueError):
            self.create()

    def test_rehashed_manifest_and_lock_cannot_hide_changed_runtime_package_closure(self):
        lock_path = self.source/'web/package-lock.json'
        manifest_path = self.source/'internal/browser/assets/manifest.json'
        original_lock, original_manifest = lock_path.read_bytes(), manifest_path.read_bytes()
        changes = [
            lambda v: v['packages']['node_modules/example'].update(dev=True),
            lambda v: v['packages']['node_modules/example'].update(optional=True),
            lambda v: v['packages']['node_modules/example'].update(link=True),
            lambda v: v['packages']['node_modules/example'].update(integrity='sha512-invalid'),
            lambda v: v['packages']['node_modules/example'].update(resolved='https://other.invalid/package.tgz'),
            lambda v: v['packages']['node_modules/example'].update(version='1.2.4'),
            lambda v: v['packages']['node_modules/example'].update(dependencies={'missing':'*'}),
            lambda v: v['packages']['node_modules/example'].update(peerDependencies={'missing':'*'}),
            lambda v: v['packages'].update({'node_modules/orphan': copy.deepcopy(v['packages']['node_modules/example'])}),
        ]
        for change in changes:
            lock_path.write_bytes(original_lock); manifest_path.write_bytes(original_manifest)
            self.mutate('web/package-lock.json', change); self.rebind_manifest('web/package-lock.json')
            with self.assertRaises(ValueError):
                self.create()

    def test_duplicate_json_keys_escaped_paths_or_unlisted_bundled_package_are_refused(self):
        with self.assertRaises(ValueError):
            inventory.load(b'{"packages":{},"packages":{}}')
        original = (self.source/'internal/browser/assets/manifest.json').read_bytes()
        for change in (lambda v: v['sources'][0].update(path='../outside'),
                lambda v: v['outputs'][0].update(name='../outside'),
                lambda v: v.update(bundled_packages=['node_modules/unknown/index.js'])):
            (self.source/'internal/browser/assets/manifest.json').write_bytes(original)
            self.mutate('internal/browser/assets/manifest.json', change)
            with self.assertRaises(ValueError):
                self.create()

    def test_embedding_search_is_bounded_and_catches_assets_crossing_chunk_boundaries(self):
        data = b'begin-exact-asset-end'
        self.binary.write_bytes(b'x'*((1 << 20)-5)+data+b'y')
        self.assertTrue(inventory.embedded(self.binary, data))
        self.assertFalse(inventory.embedded(self.binary, data+b'changed'))

    def test_committed_ui_manifest_and_runtime_lock_use_supported_closed_inventory(self):
        # Real committed UI inputs, synthetic executable and Go metadata only.
        # This catches fixture drift without compiling or executing freightctl.
        root = HERE.parent
        manifest_name = 'internal/browser/assets/manifest.json'
        manifest = json.loads((root/manifest_name).read_bytes())
        names = {manifest_name, 'third_party/ftpserverlib/UPSTREAM.json',
            *(v['path'] for v in manifest['sources']),
            *('internal/browser/assets/'+v['name'] for v in manifest['outputs'])}
        tree = {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in names}
        self.binary.write_bytes(b'qualification stand-in\x00'+b'\x00'.join(
            (root/('internal/browser/assets/'+v['name'])).read_bytes() for v in manifest['outputs']))
        result = inventory.create(root, tree, self.info, fixture.COMMIT, 'amd64', self.binary,
            hashlib.sha256(self.binary.read_bytes()).hexdigest())
        npm = {v['name'] for v in result['components'] if any(p['name'] == 'freightctl:ecosystem'
            and p['value'] == 'npm' for p in v.get('properties', []))}
        self.assertEqual(npm, {'@noble/hashes', 'react', 'react-dom', 'scheduler'})


if __name__ == '__main__':
    unittest.main()
