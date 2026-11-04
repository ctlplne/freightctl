"""Own one native FTPS source fixture for a future public byte-copy journey.

The Go helper uses real custody/FTPS; this lifecycle never opens a probe socket.
Only the exact child it starts can receive a stop signal. Not a stock peer.
"""
import hashlib
import os
from pathlib import Path
import re
import signal
import subprocess
import time

import ftps_collection_metadata as metadata
from ftps_cli_governance import require


def counter(path, mode, stopped):
    value = metadata.load(path)
    require(isinstance(value, dict) and set(value) == {'schema_version', 'kind', 'mode', 'port',
        'accepted_connections', 'budget_exhausted', 'stopped'}, 'source witness shape differs')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == 'freightctl-ftps-source-witness-v1' and value['mode'] == mode
        and type(value['port']) is int and 1 <= value['port'] <= 65535
        and type(value['accepted_connections']) is int and 0 <= value['accepted_connections'] <= 16
        and value['budget_exhausted'] is False and value['stopped'] is stopped,
        'source witness is stopped, exceeded its budget or changed meaning')
    return value


class Source:
    def __init__(self, root, private, mode, database, steps, bounded_output):
        metadata.require_environment(root)
        require(mode in ('explicit', 'implicit') and re.fullmatch('freightctl_ftps_[0-9a-f]{32}', database)
            and private.parent == root/'.private' and re.fullmatch('ftps-[0-9a-f]{32}', private.name),
            'source fixture is not its exact fresh estate')
        require(private.is_dir() and private.stat().st_mode & 0o077 == 0
            and (root/'.private').stat().st_mode & 0o077 == 0
            and not any(p.is_symlink() for p in (private, *private.parents)),
            'source fixture estate is linked or not private')
        self.root, self.private, self.mode, self.database = root, private, mode, database
        self.steps, self.bounded_output = steps, bounded_output
        self.directory = private/('source-helper-'+mode)
        self.label = 'cli-'+mode+'-collection-source'
        self.process = None
        self.closed = False
        self.cleanup_failed = False

    def start(self):
        require(self.process is None and not self.closed, 'source fixture already started')
        self.stdout = self.stderr = None
        try:
            self.directory.mkdir(mode=0o700)
            self.config = self.directory/'config.json'
            metadata.private_write(self.config, metadata.canonical({'database': self.database,
                'dsn_file': str(self.private/'pg-runtime.dsn'), 'storage': str(self.private/'custody'),
                'certificate': str(self.private/'cert.pem'), 'key': str(self.private/'key.pem'), 'mode': self.mode}))
            self.out_path, self.err_path = (self.private/(self.label+'.'+stream) for stream in ('stdout', 'stderr'))
            def output(path):
                return os.fdopen(os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'wb')
            self.stdout = output(self.out_path)
            self.stderr = output(self.err_path)
            self.began = time.monotonic()
            self.process = subprocess.Popen([str(self.private/'source-ftps'), str(self.config)],
                cwd=self.root, env=dict(os.environ, GOMAXPROCS='1', GOMEMLIMIT='192MiB'),
                stdin=subprocess.DEVNULL, stdout=self.stdout, stderr=self.stderr,
                start_new_session=True, preexec_fn=self.bounded_output)
            deadline = time.monotonic()+10
            while True:
                require(self.process.poll() is None, 'source fixture exited before readiness')
                if (self.directory/'counter.json').exists():
                    value = self.snapshot()
                    require(value['accepted_connections'] == 0, 'source contacted before producer setup')
                    return value
                require(time.monotonic() < deadline, 'source fixture readiness timed out')
                time.sleep(.05)
        except Exception:
            if self.process is not None:
                try:
                    self.stop()
                except Exception:
                    self.cleanup_failed = True
            else:
                for stream in (self.stdout, self.stderr):
                    if stream is not None:
                        stream.close()
                self.closed = True
            raise

    def snapshot(self):
        require(self.process is not None and not self.closed and self.process.poll() is None,
            'source fixture is not live')
        return counter(self.directory/'counter.json', self.mode, False)

    def stop(self):
        if self.closed:
            return
        require(self.process is not None, 'source fixture never started')
        self.closed = True
        code = 'incomplete'
        try:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGTERM)
            try:
                code = self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
                code = 'forced'
        finally:
            for stream in (self.stdout, self.stderr):
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
            self.steps.append({'name': self.label, 'exit_code': code,
                'seconds': round(time.monotonic()-self.began, 3),
                'stdout_sha256': hashlib.sha256(self.out_path.read_bytes()).hexdigest(),
                'stderr_sha256': hashlib.sha256(self.err_path.read_bytes()).hexdigest()})
        require(type(code) is int and code == 0, 'source fixture did not stop cleanly')
        return counter(self.directory/'counter.json', self.mode, True)
