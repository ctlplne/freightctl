"""Bind native go-list package closure to selected toolchain sources.

These are compiler inputs, not proof that every function survives linker pruning.
No source bodies, absolute GOROOT paths or account data enter the public result.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from ci_capacity_file import measure as measure_build_file

MAX_JSON = 32 << 20
MAX_SOURCE = 64 << 20
MAX_FILE = 16 << 20


def require(value):
    if not value:
        raise ValueError('core-go-package-inventory-invalid')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def documents(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_JSON)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value)
            value[key] = item
        return value
    def invalid(_):
        raise ValueError('core-go-package-inventory-invalid')
    decoder = json.JSONDecoder(object_pairs_hook=unique, parse_float=invalid, parse_constant=invalid)
    text = raw.decode('utf-8'); result = []; offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        require(type(value) is dict and len(result) < 4096)
        result.append(value)
    require(result)
    return result


def package_name(value):
    require(type(value) is str and len(value) <= 512 and re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.+/-]*', value)
        and all(p not in ('', '.', '..') for p in value.split('/')))
    return value


def file_hash(path):
    return measure_build_file(path,MAX_FILE)['sha256']


def capture(raw, goroot, info):
    """Read a complete native graph and stream the exact selected source files."""
    root = Path(goroot).resolve(strict=True)
    require(root.is_dir() and info['GoVersion'] == 'go1.27.3')
    packages = {}
    module_info = {v['Path']:v for v in info['Deps']}
    expected_modules = {info['Main']['Path'], *module_info}
    seen_modules = set()
    for value in documents(raw):
        name = package_name(value.get('ImportPath'))
        require(name not in packages and not any(value.get(k) for k in ('Incomplete', 'Error', 'DepsErrors', 'ForTest'))
            and not any(value.get(k) for k in ('CgoFiles', 'CFiles', 'CXXFiles', 'MFiles', 'FFiles', 'SwigFiles', 'SwigCXXFiles', 'SysoFiles')))
        imports, mapping = value.get('Imports', []), value.get('ImportMap', {})
        require(type(imports) is list and len(imports) <= 1024 and type(mapping) is dict and len(mapping) <= 1024)
        for original, resolved in mapping.items():
            package_name(original); package_name(resolved)
        imports = [package_name(mapping.get(package_name(item), item)) for item in imports]
        require(len(imports) == len(set(imports)))
        standard = value.get('Standard', False)
        require(type(standard) is bool)
        if standard:
            require(value.get('Goroot') is True and not value.get('Module'))
            module = None
        else:
            module = value.get('Module')
            require(type(module) is dict and module.get('Path') in expected_modules)
            if module['Path'] == info['Main']['Path']:
                require(module.get('Main') is True and module.get('Version', '(devel)') == '(devel)')
            else:
                expected = module_info[module['Path']]
                require(module.get('Version') == expected['Version']
                    and bool(module.get('Replace')) == bool(expected.get('Replace')))
                if expected.get('Replace'):
                    require(type(module['Replace']) is dict and module['Replace'].get('Path') == expected['Replace']['Path'])
            module = module['Path']; seen_modules.add(module)
        packages[name] = {'imports':sorted(imports), 'standard':standard, 'module':module, 'original':value}
    require(info['Path'] in packages and packages[info['Path']]['original'].get('Name') == 'main'
        and seen_modules == expected_modules)
    # Require precisely the root's reachable dependency closure, without cycles.
    seen, pending = set(), [info['Path']]
    while pending:
        name = pending.pop()
        require(name in packages)
        if name not in seen:
            seen.add(name); pending.extend(packages[name]['imports'])
    require(seen == set(packages))
    remaining = {name:set(item['imports']) for name,item in packages.items()}
    parents = {name:set() for name in packages}
    for name, imports in remaining.items():
        for child in imports:
            parents[child].add(name)
    ready = [name for name,imports in remaining.items() if not imports]; count = 0
    while ready:
        name = ready.pop(); count += 1
        for parent in parents[name]:
            remaining[parent].remove(name)
            if not remaining[parent]: ready.append(parent)
    require(count == len(packages))
    files, total = {}, 0
    def source(name):
        nonlocal total
        path = PurePosixPath(name)
        require(path.as_posix() == name and not path.is_absolute() and len(path.parts) <= 64
            and all(p not in ('', '.', '..') for p in path.parts) and '\\' not in name)
        target = root.joinpath(*path.parts)
        for parent in (target, *target.parents):
            if parent == root: break
            require(not parent.is_symlink())
        require(target.resolve(strict=True).is_relative_to(root) and target.is_file())
        if name not in files:
            require(len(files) < 8192)
            size = target.stat().st_size; total += size
            require(os.environ.get('GITHUB_ACTIONS')=='true' or total <= MAX_SOURCE)
            checksum = file_hash(target)
            require(target.stat().st_size == size)
            files[name] = checksum
        return files[name]
    source('LICENSE')
    if any(name.startswith('vendor/') for name in packages):
        source('src/vendor/modules.txt')
    standard = []
    for name, item in sorted(packages.items()):
        if not item['standard']: continue
        value = item['original']; directory = root/'src'/name
        require(type(value.get('Dir')) is str and Path(value['Dir']).resolve(strict=True) == directory.resolve(strict=True))
        selected = []
        for key in ('GoFiles', 'SFiles', 'HFiles', 'EmbedFiles'):
            names = value.get(key, [])
            require(type(names) is list and len(names) <= 1024)
            selected.extend(names)
        require(selected and all(type(v) is str for v in selected) and len(selected) == len(set(selected)))
        manifest = {filename:source('src/'+name+'/'+filename) for filename in sorted(selected)}
        standard.append({'name':name, 'version':info['GoVersion'], 'imports':[v for v in item['imports'] if packages[v]['standard']],
            'class':'compiler-provided' if name == 'unsafe' else 'toolchain-vendored' if name.startswith('vendor/') else 'standard-library',
            'source_manifest_sha256':hashlib.sha256(encoded(manifest)).hexdigest(), 'source_files':len(manifest)})
    require(standard)
    graph = {name:{k:v for k,v in item.items() if k != 'original'} for name,item in sorted(packages.items())}
    return {'packages':standard, 'package_graph_sha256':hashlib.sha256(encoded(graph)).hexdigest(),
        'package_graph_nodes':len(packages), 'toolchain_source_sha256':hashlib.sha256(encoded(files)).hexdigest(),
        'toolchain_files':files, 'toolchain_source_bytes':total}


def reopen(value, goroot):
    """Close the interval after the final external command against source changes."""
    root = Path(goroot).resolve(strict=True)
    for name, checksum in value['toolchain_files'].items():
        path = root/name
        require(path.is_file() and not path.is_symlink())
        for parent in path.parents:
            if parent == root: break
            require(not parent.is_symlink())
        require(file_hash(path) == checksum)
