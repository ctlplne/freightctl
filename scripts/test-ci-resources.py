"""Environment stand-ins only; no compiler, browser, database or scanner."""
import unittest
from ci_resources import environment


class ResourcePolicy(unittest.TestCase):
    def test_shared_machine_constraints_are_preserved_without_mutating_input(self):
        original = {'GOMAXPROCS': '1', 'GOMEMLIMIT': '192MiB', 'NODE_OPTIONS': '--max-old-space-size=192'}
        self.assertEqual(environment(original), original)
        self.assertIsNot(environment(original), original)
        self.assertEqual(environment(dict(original, GITHUB_ACTIONS='false'))['GOMEMLIMIT'], '192MiB')

    def test_github_removes_compute_caps_and_keeps_other_controls(self):
        original = {'GITHUB_ACTIONS': 'true', 'GOMAXPROCS': '1', 'GOMEMLIMIT': '192MiB',
                    'NODE_OPTIONS': '--disable-proto=throw --max-old-space-size=192',
                    'FREIGHTCTL_INFERENCE_ENABLED': 'false', 'GOTOOLCHAIN': 'local'}
        result = environment(original)
        self.assertNotIn('GOMAXPROCS', result)
        self.assertNotIn('GOMEMLIMIT', result)
        self.assertEqual(result['NODE_OPTIONS'], '--disable-proto=throw')
        self.assertEqual(result['FREIGHTCTL_INFERENCE_ENABLED'], 'false')
        self.assertEqual(result['GOTOOLCHAIN'], 'local')
        self.assertEqual(original['GOMAXPROCS'], '1')

    def test_only_heap_option_is_removed_from_node_options(self):
        result = environment({'GITHUB_ACTIONS': 'true', 'NODE_OPTIONS': '--max-old-space-size 192'})
        self.assertNotIn('NODE_OPTIONS', result)
        self.assertEqual(environment({'GITHUB_ACTIONS': 'true', 'NODE_OPTIONS': '--disable-proto=throw'})['NODE_OPTIONS'], '--disable-proto=throw')


if __name__ == '__main__':
    unittest.main()
