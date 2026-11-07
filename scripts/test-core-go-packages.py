#!/usr/bin/env python3
"""Original-file and native graph stand-ins only; no compiler or executable."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import core_go_packages as gate


def fixture(root, info):
    files = {'LICENSE':b'synthetic toolchain license', 'src/vendor/modules.txt':b'synthetic vendor manifest',
        'src/fmt/print.go':b'package fmt', 'src/unsafe/unsafe.go':b'package unsafe',
        'src/vendor/example.test/leaf/leaf.go':b'package leaf'}
    for name, body in files.items():
        path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body)
    packages = [dict(ImportPath='fmt', Name='fmt', Imports=['unsafe', 'example.test/leaf'],
        ImportMap={'example.test/leaf':'vendor/example.test/leaf'}, Standard=True, Goroot=True,
        Dir=str(root/'src/fmt'), GoFiles=['print.go']),
        dict(ImportPath='unsafe', Name='unsafe', Standard=True, Goroot=True, Dir=str(root/'src/unsafe'), GoFiles=['unsafe.go']),
        dict(ImportPath='vendor/example.test/leaf', Name='leaf', Standard=True, Goroot=True,
            Dir=str(root/'src/vendor/example.test/leaf'), GoFiles=['leaf.go'])]
    packages.append(dict(ImportPath=info['Path'], Name='main', Module={'Path':info['Main']['Path'], 'Main':True},
        Imports=['fmt', *(v['Path'] for v in info['Deps'])]))
    for module in info['Deps']:
        value = {k:copy.deepcopy(v) for k,v in module.items() if k in ('Path', 'Version', 'Replace')}
        packages.append(dict(ImportPath=module['Path'], Name='external', Module=value))
    return packages


def info():
    return dict(GoVersion='go1.27.3', Path='example.test/freightctl/cmd/freightctl',
        Main={'Path':'example.test/freightctl'}, Deps=[{'Path':'example.test/dependency', 'Version':'v1.0.0'}])


def raw(packages):
    return b'\n'.join(json.dumps(p).encode() for p in packages)+b'\n'


class GoPackageContracts(unittest.TestCase):
    def test_github_source_bytes_are_measured_without_local_size_ceilings(self):
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}), patch.object(gate,'MAX_FILE',1), patch.object(gate,'MAX_SOURCE',1):
            result=self.capture()
            self.assertGreater(result['toolchain_source_bytes'],1)
            gate.reopen(result,self.root)

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='freightctl-go-package-contract-')
        self.addCleanup(directory.cleanup); self.root = Path(directory.name).resolve()
        self.info = info(); self.packages = fixture(self.root, self.info)

    def capture(self, packages=None):
        return gate.capture(raw(self.packages if packages is None else packages), self.root, self.info)

    def test_native_graph_import_mapping_compiler_and_vendored_classes_have_bound_sources(self):
        result = self.capture()
        self.assertEqual(result, self.capture(list(reversed(self.packages))))
        self.assertEqual(result['package_graph_nodes'], 5)
        self.assertEqual({v['class'] for v in result['packages']}, {'standard-library', 'compiler-provided', 'toolchain-vendored'})
        self.assertEqual(result['packages'][0]['imports'], ['unsafe', 'vendor/example.test/leaf'])
        self.assertEqual(len(result['toolchain_files']), 5)
        self.assertNotIn(str(self.root), json.dumps(result))
        gate.reopen(result, self.root)

    def test_previous_or_unqualified_toolchain_inventory_is_not_current_evidence(self):
        for version in ('go1.26.10', 'go1.27.2', 'go1.27.3+unqualified'):
            wrong = copy.deepcopy(self.info)
            wrong['GoVersion'] = version
            with self.assertRaises(ValueError):
                gate.capture(raw(self.packages), self.root, wrong)

    def test_missing_extra_duplicate_cyclic_unresolved_or_wrong_module_graph_refuses(self):
        changes = [lambda p:p.pop(), lambda p:p.append(copy.deepcopy(p[0])),
            lambda p:p[0].update(Imports=['missing']), lambda p:p[1].update(Imports=['fmt']),
            lambda p:p.append(dict(ImportPath='orphan', Standard=False, Module={'Path':'example.test/dependency','Version':'v1.0.0'})),
            lambda p:p[-1]['Module'].update(Version='v9.0.0'),
            lambda p:p[0].update(Incomplete=True), lambda p:p[0].update(Error={'Err':'private-canary'}),
            lambda p:p[0].update(ForTest='foreign'), lambda p:p[0].update(CgoFiles=['foreign.go']),
            lambda p:p[0].update(Module={'Path':'foreign'}), lambda p:p[0].update(Goroot=False),
            lambda p:p[0].update(Imports=['unsafe','unsafe']), lambda p:p[0].update(ImportPath='../escape')]
        for change in changes:
            packages = copy.deepcopy(self.packages); change(packages)
            with self.assertRaises(ValueError):
                self.capture(packages)

    def test_source_path_directory_link_missing_file_and_selected_name_forgery_refuse(self):
        for filename in ('../unsafe/unsafe.go', '/private-canary', 'print.go/../print.go', 'bad\\name', 'missing.go'):
            packages = copy.deepcopy(self.packages); packages[0]['GoFiles'] = [filename]
            with self.assertRaises((ValueError, OSError)):
                self.capture(packages)
        packages = copy.deepcopy(self.packages); packages[0]['Dir'] = str(self.root/'src/unsafe')
        with self.assertRaises(ValueError): self.capture(packages)
        path = self.root/'src/fmt/print.go'; path.unlink(); path.symlink_to(self.root/'LICENSE')
        with self.assertRaises(ValueError): self.capture()

    def test_final_reopen_detects_changed_selected_source_license_or_vendor_manifest(self):
        for name in ('src/fmt/print.go', 'LICENSE', 'src/vendor/modules.txt'):
            result = self.capture(); path = self.root/name; original = path.read_bytes()
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError): gate.reopen(result, self.root)
            path.write_bytes(original)
        result = self.capture(); path = self.root/'src/fmt/print.go'; path.unlink(); path.symlink_to(self.root/'LICENSE')
        with self.assertRaises(ValueError): gate.reopen(result, self.root)

    def test_stream_json_duplicate_float_constant_shape_and_budgets_refuse(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":0.5}', b'[]', b'', b'{} garbage'):
            with self.assertRaises(ValueError): gate.documents(data)
        with patch.object(gate, 'MAX_JSON', 1):
            with self.assertRaises(ValueError): self.capture()
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}), patch.object(gate, 'MAX_SOURCE', 1):
            with self.assertRaises(ValueError): self.capture()
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}), patch.object(gate, 'MAX_FILE', 1):
            with self.assertRaises(ValueError): self.capture()


if __name__ == '__main__':
    unittest.main()
