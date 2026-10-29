#!/usr/bin/env python3
"""Verify and extract fetched Homebrew bottles into a private test-peer cache.

Fetch explicitly using docs/openpgp.md first. No install, post-install hook,
service or global link is executed. Existing peer manifests are never replaced.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile

os.umask(0o077)
root = Path(__file__).resolve().parents[1]
cache = root / '.cache/freightctl-brew/downloads'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--manifest', help='Explicit GnuPG OCI bottle manifest when the cache has several versions')
parser.add_argument('--output', default=str(root / '.private/freightctl-gnupg-native.json'))
args = parser.parse_args()
if platform.system() != 'Darwin' or platform.machine() != 'arm64':
    raise SystemExit('This acquisition profile requires native macOS arm64.')
manifest_files = [Path(args.manifest)] if args.manifest else list(cache.glob('*--gnupg-*.bottle_manifest.json'))
if len(manifest_files) != 1:
    raise SystemExit('Fetch the documented bottles, or select one exact --manifest.')
metadata = json.loads(manifest_files[0].read_text())
native = [m for m in metadata['manifests'] if m.get('platform', {}).get('architecture') == 'arm64'
          and m.get('platform', {}).get('os') == 'darwin']
# Select the bottle actually fetched and verified by Homebrew for this host.
gpg_archives = list(cache.glob('*--gnupg--*.tar.gz'))
selected = [(m, a) for m in native for a in gpg_archives
            if m['annotations']['sh.brew.bottle.digest'] == hashlib.sha256(a.read_bytes()).hexdigest()]
if len(selected) != 1:
    raise SystemExit('The selected GnuPG manifest and fetched native archive must match uniquely.')
tab = json.loads(selected[0][0]['annotations']['sh.brew.tab'])
names = ['gnupg'] + [x['full_name'] for x in tab['runtime_dependencies']]
items, archives = [], []
for name in names:
    matches = []
    for archive in cache.glob('*--' + name + '--*.tar.gz'):
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        for mf in cache.glob('*--' + name + '-*.bottle_manifest.json'):
            for entry in json.loads(mf.read_text())['manifests']:
                if entry.get('annotations', {}).get('sh.brew.bottle.digest') == digest:
                    matches.append((archive, digest, mf, entry))
    if len(matches) != 1:
        raise SystemExit('Missing or ambiguous fetched runtime bottle: ' + name)
    archive, digest, mf, entry = matches[0]
    if name != 'ca-certificates' and entry.get('platform', {}).get('os') != 'darwin':
        raise SystemExit('Non-macOS runtime bottle: ' + name)
    if name != 'ca-certificates' and entry.get('platform', {}).get('architecture') != 'arm64':
        raise SystemExit('Non-arm64 runtime bottle: ' + name)
    items.append({'name': name, 'bottle_tag': entry['annotations']['org.opencontainers.image.ref.name'],
                  'bottle_sha256': digest, 'source_reference': str(archive.relative_to(root)),
                  'manifest_reference': str(mf.relative_to(root)), 'license': entry['annotations'].get('sh.brew.license')})
    archives.append(archive)
output = Path(args.output).absolute()
if not output.is_relative_to(root / '.private'):
    raise SystemExit('Write the acquisition manifest inside the protected task .private directory.')
if output.exists():
    existing = json.loads(output.read_text())
    if output.is_symlink() or output.stat().st_mode & 0o077 or existing.get('dependencies') != items:
        raise SystemExit('Existing acquisition differs; preserve it and select a new --output reference.')
    for x in existing['binaries'] + existing['runtime_files']:
        p = (root / x['path']).resolve(strict=True)
        if not p.is_relative_to(root / '.cache/freightctl-gnupg-native') or hashlib.sha256(p.read_bytes()).hexdigest() != x['sha256']:
            raise SystemExit('Existing peer differs from its retained manifest; preserve and inspect it.')
    print(str(output))
    raise SystemExit(0)
# Different dependency cohorts get different directories; retained peers stay intact.
cohort = hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()[:24]
dest = root / '.cache/freightctl-gnupg-native' / cohort
dest.mkdir(parents=True, mode=0o700, exist_ok=True)
for archive in archives:
    with tarfile.open(archive) as bundle:
        bundle.extractall(dest, filter='data')
libraries = sorted(str(p) for p in dest.glob('*/*/lib') if p.is_dir())
binary_dirs = list(dest.glob('gnupg/*/bin'))
if len(binary_dirs) != 1:
    raise SystemExit('Acquired peer must contain exactly one GnuPG executable directory.')
binary_dir = binary_dirs[0]
version_home = root / '.private' / ('freightctl-gnupg-version-' + cohort)
version_home.mkdir(mode=0o700, exist_ok=True)
env = dict(os.environ, DYLD_LIBRARY_PATH=':'.join(libraries))
r = subprocess.run([str(binary_dir / 'gpg'), '--no-options', '--homedir', str(version_home), '--no-autostart', '--version'],
                   stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=5)
if r.returncode:
    raise SystemExit('Acquired GnuPG cannot start with its recorded native libraries.')
def entry(p):
    return {'path': str(p.relative_to(root)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
config = {'schema_version': 1, 'root': str(root), 'binary_dir': str(binary_dir), 'library_paths': libraries,
          'version': r.stdout.decode().splitlines()[0], 'platform': 'darwin/arm64',
          'acquisition': 'Official Homebrew bottles verified against OCI digests; isolated runtime closure without install/postinstall/global linking.',
          'dependencies': items,
          'runtime_files': [entry(p) for p in sorted(dest.glob('*/*/lib/*.dylib')) if p.is_file()],
          'binaries': [entry(binary_dir / name) for name in ['gpg', 'gpg-agent', 'gpgconf', 'gpg-connect-agent', 'gpgv']]}
with output.open('x') as stream:
    stream.write(json.dumps(config, indent=2) + '\n')
print(str(output))
