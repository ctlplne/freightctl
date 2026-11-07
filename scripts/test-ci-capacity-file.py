"""Actual tiny files and environment stand-ins;no builds or runtime peers."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ci_capacity_file import measure


class CapacityFileContracts(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory(prefix='freightctl-capacity-file-')
        self.addCleanup(directory.cleanup)
        self.root=Path(directory.name).resolve()
        self.path=self.root/'build-input'
        self.body=b'exact trusted build input'
        self.path.write_bytes(self.body)

    def test_github_measures_full_input_and_local_allowance_remains(self):
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}):
            self.assertEqual(measure(self.path,1),{'bytes':len(self.body),'sha256':hashlib.sha256(self.body).hexdigest()})
        for value in ('false','TRUE',''):
            with patch.dict(os.environ,{'GITHUB_ACTIONS':value}):
                with self.assertRaises(ValueError):measure(self.path,1)

    def test_link_directory_invalid_local_allowance_and_changed_opened_identity_refuse(self):
        linked=self.root/'link';linked.symlink_to(self.path)
        for path,bound in ((linked,100),(self.root,100),(self.path,True),(self.path,-1)):
            with self.assertRaises(ValueError):measure(path,bound)
        original=os.open
        other=self.root/'other';other.write_bytes(b'foreign source')
        def changed(path,flags):
            path.rename(self.root/'retained')
            path.write_bytes(other.read_bytes())
            return original(path,flags)
        with patch('ci_capacity_file.os.open',side_effect=changed):
            with self.assertRaises(ValueError):measure(self.path,100)

    def test_replacing_a_name_after_stream_open_cannot_rebind_its_measurement(self):
        original=hashlib.sha256
        real=original()
        path=self.path
        class ChangedDigest:
            def update(self,part):
                path.rename(path.with_name('retained'))
                path.write_bytes(b'replacement build input')
                real.update(part)
            def hexdigest(self):return real.hexdigest()
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}), patch('ci_capacity_file.hashlib.sha256',return_value=ChangedDigest()):
            with self.assertRaises(ValueError):measure(path,1)

if __name__=='__main__':unittest.main()
