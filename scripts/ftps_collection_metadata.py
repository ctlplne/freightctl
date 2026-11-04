"""Public collection metadata only: real CLI/HTTPS, zero-contact source spy.

Never runs a collection worker or claims source bytes, browser or receiver
qualification. The parent owns the fresh PostgreSQL/storage/HTTPS fixture.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re

import ftps_dispatch_qualification as dispatch
from ftps_cli_governance import read, require

COMMANDS = ('identity', 'connection-register', 'connection-register-replay', 'workflow-validate',
    'workflow-draft', 'workflow-approve', 'collection-preview', 'collection-start',
    'collection-start-replay', 'collection-api-replay', 'collection-status', 'collection-cancel',
    'collection-cancel-replay', 'connection-revoke', 'collection-api-history-replay', 'collection-final-status')
FILES = frozenset(('connection.json', 'workflow-preview.json', 'workflow.json', 'selection.json', 'start.json',
    'cancel.json', 'source-password', 'source.json', 'owner.headers', 'collection-api-replay.body',
    'collection-api-history-replay.body'))


def require_environment(root):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and platform.system() == 'Linux'
        and Path(os.environ.get('GITHUB_WORKSPACE', '.')).resolve() == root.resolve(),
        'collection metadata requires its disposable GitHub runner')


def command_suffix(name):
    if not isinstance(name, str):
        return None
    match = re.fullmatch('cli-(explicit|implicit)-collection-metadata-(.+)', name)
    return match[2] if match and match[2] in COMMANDS else None


def load(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'collection metadata duplicate evidence key')
            value[key] = item
        return value
    return json.loads(read(path, 1 << 20), object_pairs_hook=unique,
        parse_float=lambda _: require(False, 'collection metadata unexpected floating number'),
        parse_constant=lambda _: require(False, 'collection metadata invalid JSON number'))


def same(left, right):
    """JSON numbers and booleans are different, including inside snapshots."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same(v, right[k]) for k, v in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def canonical(value):
    text = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    for char in ('<', '>', '&', '\u2028', '\u2029'):
        text = text.replace(char, '\\u'+format(ord(char), '04x'))
    return text.encode()


def ref(value):
    return {'id': value['id'], 'version': value['version'], 'hash': value['definition_hash']}


def private_write(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def definition(connection):
    return {'schema_version': 1, 'name': 'Reviewed FTPS collection '+connection['ftps']['mode'],
        'steps': [], 'source': {'kind': 'ftps.collect', 'connection': ref(connection),
        'manifest': 'metadata.ready.json', 'target_directory': '/',
        'completion_contract': 'immutable-files-sha256-manifest-v1',
        'max_files': 2, 'max_file_bytes': 1024, 'max_total_bytes': 2048}}


def validate(private, mode, steps, inventory):
    require(mode in ('explicit', 'implicit') and isinstance(steps, list) and len(steps) <= 4096
        and all(isinstance(s, dict) and isinstance(s.get('name'), str) for s in steps),
        'collection metadata input shape differs')
    prefix = 'cli-'+mode+'-collection-metadata-'
    directory = private/('collection-metadata-'+mode)
    selected = [s for s in steps if s['name'].startswith(prefix)]
    require(len(selected) == len(COMMANDS) and {s['name'][len(prefix):] for s in selected} == set(COMMANDS),
        'collection metadata command closure differs')
    actual = {str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file()}
    require(isinstance(inventory, dict) and set(inventory) == actual == FILES,
        'collection metadata file closure differs')
    for name, digest in inventory.items():
        require(isinstance(name, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,100}', name),
            'collection metadata unsafe evidence name')
        path = directory/name
        require(not any(p.is_symlink() for p in (path, *path.parents)) and path.stat().st_mode & 0o077 == 0
            and hashlib.sha256(read(path, 1 << 20)).hexdigest() == digest, 'collection metadata input changed')
    for step in selected:
        out, err = (read(private/(step['name']+'.'+stream), 1 << 20) for stream in ('stdout', 'stderr'))
        require(type(step['exit_code']) is int and step['exit_code'] == 0 and err == b''
            and hashlib.sha256(out).hexdigest() == step['stdout_sha256']
            and hashlib.sha256(err).hexdigest() == step['stderr_sha256'], 'collection metadata command failed or changed')
    output = lambda name: load(private/(prefix+name+'.stdout'))
    identity = output('identity')
    require(type(identity.get('authority_revision')) is int and identity['authority_revision'] > 0
        and isinstance(identity.get('actor_id'), str) and re.fullmatch('[0-9a-f-]{36}', identity['actor_id']),
        'collection metadata authenticated identity missing')
    registered = output('connection-register')
    c = registered['resource']
    require(registered.get('replayed') is False and same(output('connection-register-replay'), dict(registered, replayed=True)),
        'collection metadata connection replay differs')
    request = load(directory/'connection.json')
    destination = request['ftps']['destination']
    require(destination['ca_reference'] == str(private/'cert.pem')
        and destination['password_reference'] == str(directory/'source-password')
        and destination['ca_sha256'] == hashlib.sha256(read(private/'cert.pem', 1 << 20)).hexdigest()
        and destination['password_sha256'] == hashlib.sha256(read(directory/'source-password', 256)).hexdigest(),
        'collection metadata original credential references differ')
    require(type(request['expected_version']) is int and request['expected_version'] == 0
        and same(c, dispatch.expected_connection_rotation(c, request, 1))
        and c['ftps']['mode'] == mode, 'collection metadata original connection differs')
    expected = definition(c)
    require(same(load(directory/'workflow-preview.json'), {'definition': expected})
        and same(load(directory/'workflow.json'), {'expected_version': 0, 'definition': expected}),
        'collection metadata reviewed workflow request differs')
    draft, approved = (output(n)['resource'] for n in ('workflow-draft', 'workflow-approve'))
    fingerprint = hashlib.sha256(canonical(expected)).hexdigest()
    require(same(draft['definition'], expected) and same(approved['definition'], expected)
        and draft['definition_hash'] == approved['definition_hash'] == fingerprint
        and draft['id'] == approved['id'] and same(draft['version'], 1) and same(approved['version'], 1)
        and draft['state'] == 'draft' and approved['state'] == 'approved'
        and same(draft['revision'], 1) and same(approved['revision'], 2)
        and same(approved['approval_authority'], identity['authority_revision']), 'collection metadata workflow changed')
    w = output('workflow-validate')
    require(same(w['definition'], expected) and w['definition_hash'] == fingerprint and w['effects'] == []
        and w['external_contact'] is False and w['approval_required'] is True
        and same(w['collection'], {'kind': 'ftps.collect', 'connection': c, 'source': expected['source']}),
        'collection metadata workflow preview changed')
    p = output('collection-preview')
    selection = {'workflow': ref(approved), 'timeout_seconds': 120,
        'expected_authority_revision': identity['authority_revision']}
    require(same(load(directory/'selection.json'), selection)
        and same(load(directory/'start.json'), {'selection': selection, 'definition_hash': p['definition_hash']})
        and same(load(directory/'cancel.json'), {'definition_hash': p['definition_hash'], 'expected_revision': 1}),
        'collection metadata original admission request differs')
    require(read(directory/'owner.headers', 512) == b'Authorization: Bearer '+read(private/'owner.token', 256)
        +b'\nIdempotency-Key: '+(prefix+'start').encode()+b'\nContent-Type: application/json\n',
        'collection metadata HTTPS original identity/key differs')
    d = p['definition']
    wanted = {'schema_version': 1, 'workflow': ref(approved), 'source': expected['source'], 'source_connection': c,
        'source_identity': hashlib.sha256((c['id']+':'+c['directory']).encode()).hexdigest(),
        'authority_revision': identity['authority_revision'], 'storage_id': d.get('storage_id'),
        'namespace_root': '/', 'timeout_seconds': 120, 'effects': []}
    require(p['external_contact'] is False and p['approval_required'] is True
        and isinstance(wanted['storage_id'], str) and re.fullmatch('[0-9a-f-]{36}', wanted['storage_id'])
        and same(d, wanted) and p['definition_hash'] == hashlib.sha256(canonical(wanted)).hexdigest(),
        'collection metadata exact source preview changed')
    first = output('collection-start')
    action = {'kind': 'workflow_collection', 'id': first['resource'].get('id'),
        'definition_hash': p['definition_hash'], 'state': 'queued', 'revision': 1}
    require(isinstance(action['id'], str) and re.fullmatch('[0-9a-f-]{36}', action['id'])
        and same(first, {'resource': action, 'replayed': False}), 'collection metadata admission differs')
    for name in ('collection-start-replay', 'collection-api-replay', 'collection-api-history-replay'):
        value = load(directory/(name+'.body')) if 'api-' in name else output(name)
        if 'api-' in name:
            require(read(private/(prefix+name+'.stdout'), 16) == b'200', 'collection metadata HTTPS replay failed')
        require(same(value, dict(first, replayed=True)), 'collection metadata saved-key result changed')
    before, after = (output(n) for n in ('collection-status', 'collection-final-status'))
    job, final = before['job'], after['job']
    require(job['id'] == final['id'] == first['resource']['id'] and same(job['definition'], d) and same(final['definition'], d)
        and job['definition_hash'] == final['definition_hash'] == p['definition_hash']
        and job['state'] == before['observed_state'] == 'queued' and same(job['revision'], 1) and before['current_authority'] is True
        and same(final, dict(job, state='cancelled', revision=2, reason='operator_cancelled'))
        and after['current_authority'] is False and after['observed_state'] == 'cancelled',
        'collection metadata current/history identity differs')
    for value in (before, after):
        j = value['job']
        require(same(j['attempts'], 0) and same(j['fence'], 0) and j['lease_owner'] == '' and j['lease_until'] is None
            and j['manifest'] is None and j['manifest_hash'] is None and j['captured'] is False
            and value['inputs'] == value['local_states'] == [] and value['business_acceptance'] == 'unknown',
            'collection metadata performed or invented acquisition')
    cancelled = output('collection-cancel')
    require(cancelled.get('replayed') is False and same(cancelled['resource'], dict(first['resource'], state='cancelled', revision=2))
        and same(output('collection-cancel-replay'), dict(cancelled, replayed=True)), 'collection metadata cancel receipt differs')
    revoked = output('connection-revoke')
    require(same(revoked['resource'], dict(c, state='revoked', revision=2)), 'collection metadata source revocation differs')
    dispatch.check_counter(load(directory/'source.json'), True)
    return {'state': 'passed', 'commands': len(COMMANDS), 'source_contacts': 0, 'attempts': 0, 'fences': 0,
        'saved_key_replays': 5, 'current_state': 'cancelled', 'source_state': 'revoked',
        'bytes_qualified': False, 'browser_qualified': False}


def exercise(root, private, mode, http_port, cert, binary, tenant, partner, owner, steps, command):
    require_environment(root)
    directory = private/('collection-metadata-'+mode)
    directory.mkdir(mode=0o700)
    prefix = 'cli-'+mode+'-collection-metadata-'
    def request(name, value):
        path = directory/(name+'.json')
        private_write(path, json.dumps(value).encode())
        return path
    def invoke(name, operation, *extra):
        return json.loads(command(prefix+name, [binary, operation, '--dsn-file', private/'pg-runtime.dsn',
            '--token-file', owner, '--tenant', tenant, '--partner', partner, '--storage', private/'custody', *extra], 20))
    identity = invoke('identity', 'identity')
    password = directory/'source-password'
    private_write(password, os.urandom(32).hex().encode())
    spy = dispatch.ContactSpy(directory/'source.json')
    try:
        connection = {'expected_version': 0, 'directory': '/collection-inbox-'+mode, 'ftps': {
            'destination': {'address': '127.0.0.1:'+str(spy.port), 'server_name': 'localhost', 'mode': mode,
                'user': 'freightctl-collection-contact-only', 'ca_reference': str(cert),
                'ca_sha256': hashlib.sha256(read(cert)).hexdigest(), 'password_reference': str(password),
                'password_sha256': hashlib.sha256(read(password)).hexdigest()},
            'staging_directory': '/collection-stage-'+mode, 'receiver_contract': {'schema_version': 1,
                'document_sha256': hashlib.sha256(b'synthetic contact-only contract; no receiver qualification').hexdigest(),
                'staging_visibility': 'receiver-private', 'rename': 'may-replace',
                'duplicates': 'receiver-deduplicates-delivery-id', 'receipt': 'exact-readback'}}}
        args = ('--request-file', request('connection', connection), '--idempotency-key', prefix+'connection')
        c = invoke('connection-register', 'connection-register', *args)['resource']
        invoke('connection-register-replay', 'connection-register', *args)
        expected = definition(c)
        invoke('workflow-validate', 'workflow-validate', '--request-file', request('workflow-preview', {'definition': expected}))
        draft = invoke('workflow-draft', 'workflow-draft', '--request-file', request('workflow',
            {'expected_version': 0, 'definition': expected}), '--idempotency-key', prefix+'workflow')['resource']
        approved = invoke('workflow-approve', 'workflow-approve', '--workflow-id', draft['id'], '--version', str(draft['version']),
            '--definition-hash', draft['definition_hash'], '--expected-revision', str(draft['revision']), '--idempotency-key', prefix+'approve')['resource']
        selection = {'workflow': ref(approved), 'timeout_seconds': 120, 'expected_authority_revision': identity['authority_revision']}
        preview = invoke('collection-preview', 'workflow-collection-preview', '--request-file', request('selection', selection))
        start = request('start', {'selection': selection, 'definition_hash': preview['definition_hash']})
        args = ('--request-file', start, '--idempotency-key', prefix+'start')
        first = invoke('collection-start', 'workflow-collection-start', *args)
        invoke('collection-start-replay', 'workflow-collection-start', *args)
        headers = directory/'owner.headers'
        private_write(headers, b'Authorization: Bearer '+read(owner)+b'\nIdempotency-Key: '+(prefix+'start').encode()+b'\nContent-Type: application/json\n')
        def api_replay(name):
            body = directory/(name+'.body')
            private_write(body, b'')
            command(prefix+name, ['curl', '-q', '--silent', '--show-error', '--noproxy', '*', '--proto', '=https',
                '--cacert', cert, '--connect-timeout', '3', '--max-time', '8', '--max-filesize', '65536',
                '--header', '@'+str(headers), '--data-binary', '@'+str(start), '--output', body,
                '--write-out', '%{http_code}', 'https://127.0.0.1:'+str(http_port)+'/v1/tenants/'+tenant+'/partners/'+partner+'/workflow-collections'], 20)
        api_replay('collection-api-replay')
        id_args = ('--collection-id', first['resource']['id'])
        status = invoke('collection-status', 'workflow-collection-status', *id_args)
        cancel = ('--request-file', request('cancel', {'definition_hash': status['job']['definition_hash'],
            'expected_revision': status['job']['revision']}), '--idempotency-key', prefix+'cancel')
        invoke('collection-cancel', 'workflow-collection-cancel', *id_args, *cancel)
        invoke('collection-cancel-replay', 'workflow-collection-cancel', *id_args, *cancel)
        invoke('connection-revoke', 'connection-revoke', '--connection-id', c['id'], '--version', str(c['version']),
            '--definition-hash', c['definition_hash'], '--expected-revision', str(c['revision']), '--idempotency-key', prefix+'revoke')
        api_replay('collection-api-history-replay')
        invoke('collection-final-status', 'workflow-collection-status', *id_args)
    finally:
        spy.stop()
    inventory = {p.name: hashlib.sha256(read(p, 1 << 20)).hexdigest() for p in sorted(directory.iterdir()) if p.is_file()}
    return validate(private, mode, steps, inventory), inventory
