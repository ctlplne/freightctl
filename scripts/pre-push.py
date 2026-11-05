#!/usr/bin/env python3
"""Fail closed before an authorized source push; never emit unredacted findings."""
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = 'imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>'
SHA = re.compile('[0-9a-f]{40}')
ZERO = '0' * 40


def run(arguments, **kwargs):
    return subprocess.run(arguments, cwd=ROOT, check=True, **kwargs)


def verify(lines, remote, url):
    if remote != 'origin' or url != 'https://github.com/ctlplne/freightctl.git':
        raise ValueError('source push destination is not authorized')
    tool = ROOT / '.cache/freightctl-gitleaks-native-8.30.1/gitleaks'
    if tool.is_symlink() or not tool.is_file():
        raise ValueError('install the pinned Gitleaks 8.30.1 tool before pushing')
    environment = {k: v for k, v in os.environ.items() if not k.startswith('GITLEAKS_')}
    version = run([str(tool), 'version'], capture_output=True, text=True,
                  timeout=10, env=environment).stdout.strip()
    if version != '8.30.1':
        raise ValueError('unexpected Gitleaks version')
    for line in lines:
        fields = line.split()
        if len(fields) != 4:
            raise ValueError('invalid push update')
        local_ref, local, remote_ref, previous = fields
        if (local_ref != 'refs/heads/main' or remote_ref != 'refs/heads/main'
                or not SHA.fullmatch(local) or not SHA.fullmatch(previous)
                or local == ZERO or previous == ZERO):
            raise ValueError('only an existing origin/main fast-forward is authorized')
        run(['git', 'merge-base', '--is-ancestor', previous, local], timeout=10)
        commits = previous + '..' + local
        identities = run(['git', 'log', '--format=%an <%ae>%n%cn <%ce>', commits],
                         capture_output=True, text=True, timeout=10).stdout.splitlines()
        if any(identity != IDENTITY for identity in identities):
            raise ValueError('outgoing author or committer is not the owner')
        run([str(tool), 'git', '.', '--log-opts=' + commits,
             '--redact', '--no-banner', '--no-color', '--ignore-gitleaks-allow'],
            env=environment, timeout=300)


def main():
    try:
        if len(sys.argv) != 3:
            raise ValueError('missing push destination')
        verify(sys.stdin, *sys.argv[1:])
        return 0
    except (ValueError, OSError, subprocess.SubprocessError):
        # Subprocess stdout is only the explicitly redacted scanner output.
        print('freightctl: pre-push refused; pinned secret scan, owner identity and fast-forward checks must pass', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
