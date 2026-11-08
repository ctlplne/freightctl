#!/usr/bin/env python3
"""Stock-peer substitution and native-source guards, without acquiring a peer."""
import copy
import unittest

import rclone_peer as peer


class IdentityGuards(unittest.TestCase):
    def setUp(self):
        self.module = dict(Path=peer.MODULE, Version=peer.VERSION, Sum=peer.SUM,
                           GoModSum=peer.MOD_SUM, Origin=dict(VCS='git',
                           URL='https://github.com/rclone/rclone', Hash=peer.REVISION,
                           Ref='refs/tags/'+peer.VERSION))
        self.binary = dict(GoVersion=peer.GO_VERSION, Path=peer.MODULE,
                           Main=dict(Path=peer.MODULE, Version=peer.VERSION, Sum=peer.SUM),
                           Settings=[dict(Key=k, Value=v) for k, v in
                                     {'GOOS': 'linux', 'GOARCH': 'arm64', '-trimpath': 'true'}.items()],
                           Deps=[dict(Path='example.invalid/dependency', Version='v1.0.0', Sum=peer.SUM)])

    def test_exact_pins(self):
        peer.validate_module(self.module)
        peer.validate_binary(self.binary, 'arm64')

    def test_same_version_other_source_or_origin_is_refused(self):
        for field in ('Path', 'Version', 'Sum', 'GoModSum'):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.module)
                changed[field] += '-changed'
                with self.assertRaises(ValueError):
                    peer.validate_module(changed)
        for field in ('VCS', 'URL', 'Hash', 'Ref'):
            with self.subTest(origin=field):
                changed = copy.deepcopy(self.module)
                changed['Origin'][field] += '-changed'
                with self.assertRaises(ValueError):
                    peer.validate_module(changed)

    def test_wrong_binary_configuration_and_replacements_are_refused(self):
        changes = [lambda v: v.update(GoVersion='go1.26.0'),
                   lambda v: v.update(Path='example.invalid/fork'),
                   lambda v: v['Main'].update(Sum='h1:changed'),
                   lambda v: v['Main'].update(Replace={}),
                   lambda v: v['Settings'].append(dict(Key='-tags', Value='webdavonly')),
                   lambda v: v['Settings'].append(dict(Key='GOOS', Value='linux')),
                   lambda v: v['Settings'][1].update(Value='amd64'),
                   lambda v: v['Deps'][0].update(Replace={}),
                   lambda v: v.update(Deps=[])]
        for change in changes:
            changed = copy.deepcopy(self.binary)
            change(changed)
            with self.assertRaises(ValueError):
                peer.validate_binary(changed, 'arm64')

    def test_local_and_cross_candidates_are_refused(self):
        commit = 'a'*40
        env = dict(GITHUB_ACTIONS='true', GITHUB_SHA=commit)
        self.assertEqual(peer.validate_native(env, 'Linux', 'aarch64', commit), 'arm64')
        self.assertEqual(peer.validate_native(env, 'Linux', 'x86_64', commit), 'amd64')
        for system, machine, actual, supplied in [('Darwin', 'arm64', commit, env),
                ('Linux', 'aarch64', 'b'*40, env), ('Linux', 'riscv64', commit, env),
                ('Linux', 'aarch64', commit, {}), ('Linux', 'x86_64', 'main', env)]:
            with self.assertRaises(ValueError):
                peer.validate_native(supplied, system, machine, actual)

    def test_incomplete_or_ambiguous_dependency_inventory_is_refused(self):
        for field in ('Path', 'Version', 'Sum'):
            changed = copy.deepcopy(self.binary)
            del changed['Deps'][0][field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                peer.validate_binary(changed, 'arm64')
        changed = copy.deepcopy(self.binary)
        changed['Deps'].append(copy.deepcopy(changed['Deps'][0]))
        with self.assertRaises(ValueError):
            peer.validate_binary(changed, 'arm64')


if __name__ == '__main__':
    unittest.main()
