"""Measure trusted build inputs on GitHub;preserve local file allowances.

Callers still enforce their existing root,inventory and evidence contracts.
Never use this for bounded untrusted JSON,archives or protocol payloads.
"""
import hashlib
import os
from pathlib import Path
import stat


def measure(path, local_limit):
    path=Path(path)
    if type(local_limit) is not int or local_limit < 0:
        raise ValueError('build-file-inventory-invalid')
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size < 0:
        raise ValueError('build-file-inventory-invalid')
    limit=None if os.environ.get('GITHUB_ACTIONS')=='true' else local_limit
    if limit is not None and before.st_size > limit:
        raise ValueError('local-build-file-allowance-exceeded')
    identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
    checksum,count=hashlib.sha256(),0
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb') as stream:
        if identity(os.fstat(stream.fileno()))!=identity(before):
            raise ValueError('build-file-changed')
        while part:=stream.read(1<<20):
            count+=len(part)
            if count > before.st_size:
                raise ValueError('build-file-changed')
            checksum.update(part)
        if (count!=before.st_size or identity(os.fstat(stream.fileno()))!=identity(before)
                or identity(path.lstat())!=identity(before)):
            raise ValueError('build-file-changed')
    return {'sha256':checksum.hexdigest(),'bytes':count}
