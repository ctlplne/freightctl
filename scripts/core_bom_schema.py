"""Independent, offline CycloneDX schema validation on disposable GitHub only."""
import hashlib
from importlib import metadata
import json
import os
import platform
import sys

PINS_SHA256 = '2d2f12e73c0bd1037c3dc393cb7195bae708c4b279088f0f1a3176c27e63f60d'
SCHEMAS = ('bom-1.6.schema.json', 'spdx.schema.json', 'jsf-0.82.schema.json')
ERROR = 'independent-core-bom-schema-invalid'


def require(value):
    if not value:
        raise ValueError(ERROR)


def read(path, maximum=1 << 20):
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents))
        and 0 < path.stat().st_size <= maximum)
    return path.read_bytes()


def load(data):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            require(key not in result)
            result[key] = item
        return result
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: require(False))


def sources(root):
    raw = read(root/'scripts/bom-validator-pins.json')
    require(hashlib.sha256(raw).hexdigest() == PINS_SHA256)
    pins = load(raw)
    require(pins['schema_version'] == 1 and pins['python'] == '3.12'
        and hashlib.sha256(read(root/'scripts/bom-validator-requirements.txt')).hexdigest() == pins['requirements_sha256'])
    directory = root/'third_party/cyclonedx-schema'
    raw = read(directory/'UPSTREAM.json')
    require(hashlib.sha256(raw).hexdigest() == pins['schema_upstream_manifest_sha256'])
    upstream = load(raw)
    require(upstream['commit'] == '8a27bfd1be5be0dcb2c208a34d2f4fa0b6d75bd7'
        and upstream['tag'] == '1.6.1'
        and {p.name for p in directory.iterdir()} == {*SCHEMAS, 'LICENSE', 'UPSTREAM.json'}
        and {v['path'] for v in upstream['files']} == {*SCHEMAS, 'LICENSE'})
    docs = {}
    for item in upstream['files']:
        raw = read(directory/item['path'])
        require(len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256'])
        if item['path'] in SCHEMAS:
            value = load(raw)
            require(value.get('$id') == 'http://cyclonedx.org/schema/'+item['path']
                and value.get('$schema') == 'http://json-schema.org/draft-07/schema#')
            docs[item['path']] = value
    return pins, docs


def require_runtime(pins):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and platform.system() == 'Linux'
        and platform.machine() in ('x86_64', 'aarch64') and sys.version_info[:2] == (3, 12))
    require(all(metadata.version(item['name']) == item['version'] for item in pins['packages']))


def offline_registry(docs):
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource
    def deny(uri):
        # No file, HTTP, registry, model or other fallback can be triggered by a
        # schema reference. Only the three pinned in-memory schemas exist.
        raise NoSuchResource(ref=uri)
    return Registry(retrieve=deny).with_resources(
        (doc['$id'], Resource.from_contents(doc)) for doc in docs.values())


def engine(docs):
    from jsonschema import Draft7Validator, FormatChecker
    for doc in docs.values():
        Draft7Validator.check_schema(doc)
    return Draft7Validator(docs[SCHEMAS[0]], registry=offline_registry(docs), format_checker=FormatChecker())


def validate(root, document):
    try:
        pins, docs = sources(root)
        require_runtime(pins)
        validator = engine(docs)
        require(validator.is_valid(document))
        # A valid report from an unconfigured/pass-through parser is not proof.
        # These controls must fail under the same actual stock validator.
        for changed in ({'bomFormat': 'invented', 'specVersion': '1.6'},
                {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': [{'type': 'invented', 'name': 'control'}]},
                {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'unexpected': 'control'}):
            require(not validator.is_valid(changed))
        return {'engine': 'python-jsonschema', 'version': '4.26.0', 'python': '3.12',
            'schema_upstream_manifest_sha256': pins['schema_upstream_manifest_sha256'],
            'requirements_sha256': pins['requirements_sha256']}
    except Exception:
        # Validation errors may contain original values or paths. Public native
        # results expose only the fixed phase/check and bound manifest hashes.
        raise ValueError(ERROR) from None
