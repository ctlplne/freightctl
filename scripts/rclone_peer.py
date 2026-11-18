"""Stock peer identity checks and redacted scan diagnostics."""
import re

MODULE = 'github.com/rclone/rclone'
VERSION = 'v1.76.0'
REVISION = 'e982ff36668f5130d94b4f70409babb3d964df42'
SUM = 'h1:Gabl7KmhxyOXyMtFNA/s6wZ3LZ/2x0NP7xZLNEW3Guo='
MOD_SUM = 'h1:PoNZIA6Rv+01jY+WxLTz08i/QBEPz/6L5s1aD24Z5tc='
GO_VERSION = 'go1.27.4'


def validate_module(value):
    expected = dict(Path=MODULE, Version=VERSION, Sum=SUM, GoModSum=MOD_SUM)
    if any(value.get(k) != v for k, v in expected.items()) or value.get('Error'):
        raise ValueError('stock peer module identity differs')
    origin = value.get('Origin', {})
    if any(origin.get(k) != v for k, v in dict(
            VCS='git', URL='https://github.com/rclone/rclone',
            Hash=REVISION, Ref='refs/tags/'+VERSION).items()):
        raise ValueError('stock peer upstream origin differs')


def validate_binary(value, arch):
    main = value.get('Main', {})
    if (arch not in ('amd64', 'arm64') or value.get('GoVersion') != GO_VERSION
            or value.get('Path') != MODULE or main.get('Path') != MODULE
            or main.get('Version') != VERSION or main.get('Sum') != SUM
            or main.get('Replace') is not None):
        raise ValueError('stock peer executable identity differs')
    rows = value.get('Settings', [])
    if len({r['Key'] for r in rows}) != len(rows):
        raise ValueError('ambiguous executable build settings')
    settings = {r['Key']: r['Value'] for r in rows}
    if (settings.get('GOOS') != 'linux' or settings.get('GOARCH') != arch
            or settings.get('-trimpath') != 'true' or settings.get('-tags', '')
            or settings.get('vcs.modified') == 'true'):
        raise ValueError('stock peer native configuration differs')
    dependencies = value.get('Deps', [])
    if not dependencies or any(d.get('Replace') is not None for d in dependencies):
        raise ValueError('stock peer dependency inventory is missing or replaced')
    paths = [d.get('Path') for d in dependencies]
    if (len(set(paths)) != len(paths) or any(not d.get('Path') or not d.get('Version')
            or not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', d.get('Sum', ''))
            for d in dependencies)):
        raise ValueError('stock peer dependency inventory is incomplete or ambiguous')


def validate_native(environ, system, machine, commit):
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(machine)
    if (environ.get('GITHUB_ACTIONS') != 'true' or system != 'Linux'
            or arch is None or not re.fullmatch('[0-9a-f]{40}', commit)
            or environ.get('GITHUB_SHA') != commit):
        raise ValueError('stock peer requires its exact native Actions candidate')
    return arch


def scan_finding_ids(lines):
    """Extract advisory IDs from the pinned converter's result headings."""
    sections = {f'=== {scope.title()} Results ==='.encode(): scope
                for scope in ('symbol', 'package', 'module')}
    findings = {scope: set() for scope in sections.values()}
    title = re.compile(rb'Vulnerability #[1-9][0-9]*: (GO-[0-9]{4}-[0-9]{4,8})')
    scope = None
    for line in lines:
        line = line.rstrip(b'\r\n')
        if line.startswith(b'=== '):
            scope = sections.get(line)
        elif scope is not None:
            match = title.fullmatch(line)
            if match:
                findings[scope].add(match[1].decode('ascii'))
    return {scope: sorted(ids) for scope, ids in findings.items()}
