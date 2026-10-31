"""Unique native operation outputs and independently checked recorded hashes."""
from pathlib import Path
import hashlib
import re


class NativeEvidence:
    def __init__(self, directory, steps):
        self.directory = Path(directory)
        self.steps = steps
        self.reserved = set()

    def reserve(self, name):
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', name):
            raise ValueError('invalid native output label')
        if name in self.reserved:
            raise ValueError('native output label already reserved: ' + name)
        for extension in ('stdout', 'stderr', 'json'):
            p = self.directory / (name + '.' + extension)
            if p.exists() or p.is_symlink():
                raise ValueError('native output already exists: ' + p.name)
        self.reserved.add(name)

    def verify(self):
        names = [step['name'] for step in self.steps]
        if len(set(names)) != len(names) or set(names) != self.reserved:
            raise ValueError('native steps are duplicate, unregistered or incomplete')
        count = 0
        for step in self.steps:
            for extension, key in (('stdout', 'stdout_sha256'), ('stderr', 'stderr_sha256'), ('json', 'response_sha256')):
                if key not in step:
                    if extension != 'json':
                        raise ValueError('native output hash missing: ' + step['name'])
                    continue
                p = self.directory / (step['name'] + '.' + extension)
                if not p.is_file() or p.is_symlink():
                    raise ValueError('native output missing or unsafe: ' + p.name)
                if hashlib.sha256(p.read_bytes()).hexdigest() != step[key]:
                    raise ValueError('native output checksum mismatch: ' + p.name)
                count += 1
        return count
