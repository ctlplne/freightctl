"""CycloneDX 1.6 core inventory from verified build info and embedded UI bytes.

Not a deployment SBOM: OS, external programs, build tools, model inputs, complete
license analysis, signing and disconnected installation remain separate gates.
"""
import base64
import hashlib
import json
from pathlib import PurePosixPath
import re


def require(value):
    if not value:
        raise ValueError('core-component-inventory-invalid')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()+b'\n'


def file_bytes(source, tree, name):
    path = PurePosixPath(name)
    require(path.as_posix() == name and not path.is_absolute() and '..' not in path.parts
        and name in tree and '\\' not in name)
    target = source.joinpath(*path.parts)
    require(target.is_file() and not target.is_symlink() and target.stat().st_size <= 8 << 20)
    data = target.read_bytes()
    require(hashlib.sha256(data).hexdigest() == tree[name])
    return data


def load(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: require(False))


def embedded(binary, data):
    """Exact embedded-byte check with at most one asset plus a 1MiB buffer."""
    require(data and len(data) <= 8 << 20)
    tail = b''
    with binary.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            window = tail+chunk
            if data in window:
                return True
            tail = window[-(len(data)-1):] if len(data) > 1 else b''
    return False


def create(source, tree, info, commit, arch, binary, binary_sha):
    # Caller independently verifies native build info, modules, final binary
    # hash and both clean source copies. Never reinterpret Go h1 directory
    # hashes as archive/file SHA256 checksums.
    require(re.fullmatch('[0-9a-f]{40}', commit) and arch in ('amd64', 'arm64')
        and re.fullmatch('[0-9a-f]{64}', binary_sha))
    package = load(file_bytes(source, tree, 'web/package.json'))
    lock = load(file_bytes(source, tree, 'web/package-lock.json'))
    manifest = load(file_bytes(source, tree, 'internal/browser/assets/manifest.json'))
    require(lock.get('lockfileVersion') == 3 and type(lock.get('packages')) is dict
        and 1 <= len(lock['packages']) <= 1024 and manifest.get('schema_version') == 1
        and lock['packages']['']['dependencies'] == package['dependencies'])
    prod = {}
    for path, value in lock['packages'].items():
        if not path or value.get('dev') is True:
            continue
        name = path.removeprefix('node_modules/')
        require(path == 'node_modules/'+name and re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9._-]+', name)
            and type(value.get('version')) is str and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value['version'])
            and not any(value.get(key) for key in ('link', 'optional', 'devOptional', 'peerDependenciesMeta'))
            and type(value.get('resolved')) is str
            and value['resolved'] == 'https://registry.npmjs.org/'+name+'/-/'+name.rsplit('/', 1)[-1]+'-'+value['version']+'.tgz'
            and type(value.get('integrity')) is str and value['integrity'].startswith('sha512-'))
        checksum = base64.b64decode(value['integrity'][7:], validate=True)
        require(len(checksum) == 64)
        prod[name] = (value, checksum.hex())
    require(1 <= len(prod) <= 512 and all(name in prod and prod[name][0]['version'] == version
        for name, version in package['dependencies'].items()))
    reached, pending = set(), list(package['dependencies'])
    while pending:
        name = pending.pop()
        require(name in prod)
        if name in reached:
            continue
        reached.add(name)
        dependencies = prod[name][0].get('dependencies', {})
        peers = prod[name][0].get('peerDependencies', {})
        require(type(dependencies) is dict and type(peers) is dict and len(dependencies)+len(peers) <= 128)
        pending.extend((*dependencies, *peers))
    require(reached == set(prod))
    # The committed bundler manifest names the packages actually used. Its
    # sources and outputs must match the committed tree and final executable.
    require(type(manifest.get('sources')) is list and 1 <= len(manifest['sources']) <= 512
        and type(manifest.get('outputs')) is list and 1 <= len(manifest['outputs']) <= 32
        and type(manifest.get('bundled_packages')) is list and len(manifest['bundled_packages']) <= 4096)
    seen = set()
    for item in manifest['sources']:
        name = item['path']
        require(name not in seen and name.startswith('web/') and item['sha256'] == tree.get(name))
        seen.add(name)
        file_bytes(source, tree, name)
    require({'web/package.json', 'web/package-lock.json'} <= seen)
    bundled = set()
    for path in manifest['bundled_packages']:
        require(type(path) is str and path.startswith('node_modules/') and '..' not in PurePosixPath(path).parts)
        parts = path.split('/')[1:]
        name = '/'.join(parts[:2]) if parts[0].startswith('@') else parts[0]
        require(name in prod and len(parts) > (2 if parts[0].startswith('@') else 1))
        bundled.add(name)
    require(bundled == set(prod))
    components, refs, output_names = [], [], set()
    def component(kind, name, version, properties=(), hashes=None):
        ref = hashlib.sha256(encoded([kind, name, version])).hexdigest()
        value = {'type': kind, 'bom-ref': ref, 'name': name, 'version': version}
        if properties:
            value['properties'] = [{'name': key, 'value': value} for key, value in properties]
        if hashes:
            value['hashes'] = hashes
        components.append(value); refs.append(ref)
    for item in manifest['outputs']:
        name = item['name']
        require(type(name) is str and re.fullmatch('[A-Za-z0-9._-]+', name) and name not in output_names)
        output_names.add(name)
        data = file_bytes(source, tree, 'internal/browser/assets/'+name)
        require(type(item['size']) is int and item['size'] == len(data)
            and item['sha256'] == hashlib.sha256(data).hexdigest() and embedded(binary, data))
        component('file', 'browser/'+name, commit, hashes=[{'alg': 'SHA-256', 'content': item['sha256']}])
    require({'internal/browser/assets/'+name for name in output_names}|{'internal/browser/assets/manifest.json'}
        == {name for name in tree if name.startswith('internal/browser/assets/')})
    for item in sorted(info['Deps'], key=lambda v: v['Path']):
        props = [('freightctl:ecosystem', 'go')]
        if 'Replace' in item:
            local = {name: value for name, value in tree.items() if name.startswith('third_party/ftpserverlib/')}
            require(local)
            props.extend([('freightctl:local-tree-sha256', hashlib.sha256(encoded(local)).hexdigest()),
                ('freightctl:local-replacement', './third_party/ftpserverlib')])
        else:
            props.append(('freightctl:go-module-h1-directory-hash', item['Sum']))
        component('library', item['Path'], item['Version'], props)
    for name, (value, checksum) in sorted(prod.items()):
        component('library', name, value['version'], [('freightctl:ecosystem', 'npm'),
            ('freightctl:checksum-source', 'committed package-lock integrity; not fetched by this inventory gate')],
            [{'alg': 'SHA-512', 'content': checksum}])
    require(len(refs) == len(set(refs)))
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
        'metadata': {'lifecycles': [{'phase': 'post-build'}],
            'tools': {'components': [{'type': 'application', 'name': 'freightctl-core-inventory', 'version': '1'}]},
            'component': {'type': 'application', 'bom-ref': 'freightctl-core', 'name': 'freightctl', 'version': commit,
                'hashes': [{'alg': 'SHA-256', 'content': binary_sha}], 'properties': [
                    {'name': 'freightctl:architecture', 'value': arch},
                    {'name': 'freightctl:go-toolchain', 'value': info['GoVersion']},
                    {'name': 'freightctl:scope', 'value': 'Verified embedded Go modules and exact UI assets/production lock packages only; excludes OS,external programs,build tools,models,full license analysis,signing and deployment qualification.'}]}},
        'components': components,
        'dependencies': [{'ref': 'freightctl-core', 'dependsOn': sorted(refs)}]}
