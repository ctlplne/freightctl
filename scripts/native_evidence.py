"""Unique native operation outputs and independently checked recorded hashes."""
from pathlib import Path
import hashlib
import json
import os
import re
import stat


class NativeEvidence:
    def __init__(self, directory, steps):
        self.directory = Path(directory)
        self.steps = steps
        self.reserved = set()

    def failure_summary(self, name):
        """Closed diagnosis only; never publish raw command output or paths."""
        unavailable = {'kind': 'native-command-failure', 'category': 'unavailable'}
        matches = [step for step in self.steps if step.get('name') == name]
        if name not in self.reserved or len(matches) != 1:
            return unavailable
        step = matches[0]
        if any(type(step.get(k)) is not int or not -255 <= step[k] <= 255
               for k in ('exit_code', 'expected_exit_code')):
            return unavailable
        bodies, digests = {}, {}
        try:
            for extension in ('stdout', 'stderr'):
                path = self.directory / (name+'.'+extension)
                flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
                if path.is_symlink():
                    return unavailable
                with os.fdopen(os.open(path, flags), 'rb') as source:
                    info = os.fstat(source.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 64 << 10:
                        return unavailable
                    body = source.read((64 << 10)+1)
                    if len(body) != info.st_size:
                        return unavailable
                    digest = hashlib.sha256(body).hexdigest()
                    if digest != step.get(extension+'_sha256'):
                        return unavailable
                    bodies[extension] = body
                    digests[extension+'_sha256'] = digest
        except (OSError, ValueError):
            return unavailable
        exact = {
            b'': 'empty-stderr',
            b'freightctl: permission denied\n': 'permission-denied',
            b'freightctl: unauthorized\n': 'unauthorized',
            b'freightctl: required database isolation is not active\n': 'database-isolation',
            b'freightctl: resource revision changed\n': 'revision-changed',
            b'freightctl: operation does not match the current resource state\n': 'state-conflict',
            b'freightctl: current collection authority, exact input and live execution lease required\n': 'collection-authority-input-lease',
        }
        error = bodies['stderr']
        category = exact.get(error, 'unclassified')
        sql = {b'23514': 'postgres-check', b'23503': 'postgres-reference',
               b'23505': 'postgres-unique', b'42501': 'postgres-permission',
               b'40001': 'postgres-serialization', b'40P01': 'postgres-deadlock',
               b'57014': 'postgres-cancelled', b'22023': 'postgres-input'}
        codes = [code for code in sql if b'(SQLSTATE '+code+b')' in error]
        if len(codes) == 1:
            category = sql[codes[0]]
        elif len(codes) > 1:
            category = 'ambiguous-postgres-error'
        return {'kind': 'native-command-failure', 'category': category,
                'exit_code': step['exit_code'], 'expected_exit_code': step['expected_exit_code'], **digests}

    def reserve(self, name):
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', name):
            raise ValueError('invalid native output label')
        if name in self.reserved:
            raise ValueError('native output label already reserved: ' + name)
        for extension in ('stdout', 'stderr', 'json', 'browser.json'):
            p = self.directory / (name + '.' + extension)
            if p.exists() or p.is_symlink():
                raise ValueError('native output already exists: ' + p.name)
        self.reserved.add(name)

    def capture_browser(self, name, report):
        """Keep this invocation before a later browser overwrites its common report."""
        matches = [s for s in self.steps if s['name'] == name]
        if name not in self.reserved or len(matches) != 1:
            raise ValueError('browser report requires one reserved recorded command')
        with Path(report).open('rb') as source:
            data = source.read((1 << 20) + 1)
        if len(data) > 1 << 20:
            raise ValueError('browser report exceeds evidence bound')
        target = self.directory / (name + '.browser.json')
        with target.open('xb') as output:
            output.write(data)
        matches[0]['browser_report_sha256'] = hashlib.sha256(data).hexdigest()
        result = json.loads(data)
        if (result.get('state') != 'passed' or result.get('runtime_errors') != []
                or result.get('external_egress') != []):
            raise ValueError('browser failed or reported page errors/external egress: ' + name)

    def verify(self):
        names = [step['name'] for step in self.steps]
        if len(set(names)) != len(names) or set(names) != self.reserved:
            raise ValueError('native steps are duplicate, unregistered or incomplete')
        count = 0
        for step in self.steps:
            for extension, key in (('stdout', 'stdout_sha256'), ('stderr', 'stderr_sha256'), ('json', 'response_sha256'), ('browser.json', 'browser_report_sha256')):
                if key not in step:
                    if extension in ('stdout', 'stderr'):
                        raise ValueError('native output hash missing: ' + step['name'])
                    continue
                p = self.directory / (step['name'] + '.' + extension)
                if not p.is_file() or p.is_symlink():
                    raise ValueError('native output missing or unsafe: ' + p.name)
                if hashlib.sha256(p.read_bytes()).hexdigest() != step[key]:
                    raise ValueError('native output checksum mismatch: ' + p.name)
                count += 1
        return count
