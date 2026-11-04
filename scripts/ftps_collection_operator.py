"""Actual operator capture fixture and independently reopened original evidence.

Runs only in a disposable Linux GitHub estate. Curl is the producer; the source
server is ordinary freightctl, not an independent vendor. No downstream receipt
or business acceptance is inferred from a local copy.
"""
import hashlib
import json
from pathlib import Path
import re
import uuid
from urllib.parse import urlsplit

import ftps_collection_metadata as metadata
import ftps_collection_source as source
from ftps_cli_governance import read, require

AUDITS = tuple('ftps-operator-'+name for name in ('form', 'draft', 'approval', 'queue', 'work', 'captured'))
DECISIONS = ('draft', 'approve', 'queue', 'work')
READS = ('workflow-preview', 'job-preview', 'queued-view', 'captured-view')
COMMANDS = ('producer-token', 'producer-enroll', 'identity', 'producer-identity', 'upload-source', 'upload-ready',
    'source-before', 'ready-before', 'connection-register', 'connection-register-replay', 'browser', 'status',
    'consumer-readback', 'producer-readback', 'ready-readback', 'source-after', 'ready-after', 'source')
FILES = frozenset(('producer.token', 'curl.conf', 'source.csv', 'operator.ready.json', 'connection.json',
    'producer.headers', 'owner.headers', 'consumer.body', 'producer.body', 'ready.body', 'config.json',
    'raw/ftps-operator-result.json', 'raw/onboarding-exchange-browser.json', 'raw/onboarding-exchange-review.png',
    *('raw/'+name+'-axe.json' for name in AUDITS), *('raw/'+name+'.body' for name in READS),
    *('raw/'+name+'.'+suffix for name in READS for suffix in ('json', 'request', 'headers')),
    *('raw/ftps-operator-'+name+'-'+str(attempt)+'.'+suffix
        for name in DECISIONS for attempt in (0, 1) for suffix in ('headers', 'request', 'json'))))
UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
STAGES = frozenset(('certificate', 'browser-launch', 'context-create', 'login-navigation', 'login-identity',
    'login-credential', 'login-submit', 'files-ready', 'runtime-checks', 'success-screenshot', 'failure-capture',
    'record-write', 'context-close', 'browser-close', 'complete', 'definition',
    *('operator-'+s for s in ('definition', 'counter-before', 'form', 'preview', 'draft', 'approval', 'queue',
        'counter-queued', 'work', 'inspect', 'counter-after', 'record'))))


def command_suffix(name):
    match = re.fullmatch('cli-(explicit|implicit)-collection-operator-(.+)', name or '')
    if match and match[2] in COMMANDS:
        return match[2]
    match = re.fullmatch('cli-(explicit|implicit)-collection-source', name or '')
    return 'source' if match else 'build' if name == 'collection-source-build' else None


def safe_observation(value):
    if (type(value) is not dict or type(value.get('mode')) is not str or value['mode'] not in ('explicit', 'implicit')
            or type(value.get('stage')) is not str or value['stage'] not in STAGES):
        return None
    if value.get('kind') == 'ftps-operator-browser-progress' and set(value) == {'kind', 'mode', 'stage'}:
        return dict(value)
    if (value.get('kind') != 'ftps-operator-browser-failure'
            or set(value) != {'kind', 'mode', 'stage', 'error_kind', 'source_file', 'source_line'}
            or type(value.get('error_kind')) is not str or value['error_kind'] not in ('assertion', 'timeout', 'syntax', 'other')):
        return None
    file, line = value['source_file'], value['source_line']
    if file is None and line is None or type(file) is str and file in ('driver', 'wrapper') and type(line) is int and 1 <= line <= 4000:
        return dict(value)
    return None


def digest(path, limit=1 << 20):
    require(not any(p.is_symlink() for p in (path, *path.parents)) and path.is_file()
        and 0 <= path.stat().st_size <= limit, 'operator evidence is linked, missing or oversized')
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def payload(mode):
    return ('account,amount,mode\n0001,1.01,'+mode+'\n').encode()


def curl_config(private, token, producer):
    return ('user = '+json.dumps(producer['tenant_id']+'/'+producer['partner_id']+':'+read(token, 256).decode())
        +'\ncacert = '+json.dumps(str(private/'cert.pem'))+'\nssl-reqd\ntls-max = "1.3"\nnoproxy = "*"\n'
        +'connect-timeout = 3\nmax-time = 10\nsilent\nshow-error\n').encode()


def connection(private, directory, mode, port, producer):
    return {'expected_version': 0, 'directory': '/', 'ftps': {
        'destination': {'address': '127.0.0.1:'+str(port), 'server_name': 'localhost', 'mode': mode,
            'user': producer['tenant_id']+'/'+producer['partner_id'], 'ca_reference': str(private/'cert.pem'),
            'ca_sha256': digest(private/'cert.pem'), 'password_reference': str(directory/'producer.token'),
            'password_sha256': digest(directory/'producer.token')},
        'staging_directory': '/unused-collection-stage', 'receiver_contract': {'schema_version': 1,
            'document_sha256': hashlib.sha256(b'qualification source only; no sending or receiver contract claim').hexdigest(),
            'staging_visibility': 'receiver-private', 'rename': 'may-replace',
            'duplicates': 'receiver-deduplicates-delivery-id', 'receipt': 'exact-readback'}}}


def definition(c):
    value = metadata.definition(c)
    value['name'] = 'Operator FTPS capture '+c['ftps']['mode']
    value['source']['manifest'] = 'operator.ready.json'
    return value


def inventory(private, mode):
    directory, helper = private/('collection-operator-'+mode), private/('source-helper-'+mode)
    return {'operator': {str(p.relative_to(directory)): digest(p, 6 << 20)
            for p in sorted(directory.rglob('*')) if p.is_file()},
        'source': {p.name: digest(p) for p in sorted(helper.iterdir()) if p.is_file()},
        'helper_sha256': digest(private/'source-ftps', 64 << 20)}


def exercise(root, private, mode, database, http_port, cert, binary, tenant, partner, owner, steps, command, bounded_output):
    metadata.require_environment(root)
    directory = private/('collection-operator-'+mode)
    directory.mkdir(mode=0o700)
    (directory/'raw').mkdir(mode=0o700)
    prefix = 'cli-'+mode+'-collection-operator-'
    producer_tenant, producer_partner = str(uuid.uuid4()), str(uuid.uuid4())
    producer_token = directory/'producer.token'
    command(prefix+'producer-token', [binary, 'token', '--token-file', producer_token], 20)
    command(prefix+'producer-enroll', [binary, 'enroll', '--admin-dsn-file', private/'pg-admin.dsn',
        '--tenant', producer_tenant, '--partner', producer_partner, '--token-file', producer_token], 20)
    def invoke(label, operation, *extra, producer=False):
        return json.loads(command(prefix+label, [binary, operation, '--dsn-file', private/'pg-runtime.dsn',
            '--token-file', producer_token if producer else owner,
            '--tenant', producer_tenant if producer else tenant, '--partner', producer_partner if producer else partner,
            '--storage', private/'custody', *extra], 20))
    identity, producer = invoke('identity', 'identity'), invoke('producer-identity', 'identity', producer=True)
    metadata.private_write(directory/'source.csv', payload(mode))
    manifest = {'schema_version': 1, 'batch_id': str(uuid.uuid4()), 'files': [{'name': 'source.csv',
        'size_bytes': len(payload(mode)), 'sha256': hashlib.sha256(payload(mode)).hexdigest()}]}
    metadata.private_write(directory/'operator.ready.json', metadata.canonical(manifest))
    require(producer['tenant_id'] == producer_tenant and producer['partner_id'] == producer_partner,
        'operator producer enrollment identity differs')
    metadata.private_write(directory/'curl.conf', curl_config(private, producer_token, producer))
    if not (private/'source-ftps').exists():
        command('collection-source-build', ['sh', 'scripts/go.sh', 'build', '-p', '1', '-trimpath',
            '-buildvcs=false', '-o', private/'source-ftps', './scripts/peers/ftps-source'], 120)
    witness = source.Source(root, private, mode, database, steps, bounded_output)
    try:
        active = witness.start()
        for label, name in (('source', 'source.csv'), ('ready', 'operator.ready.json')):
            command(prefix+'upload-'+label, ['curl', '-q', '--config', directory/'curl.conf',
                '--upload-file', directory/name, ('ftps' if mode == 'implicit' else 'ftp')
                +'://127.0.0.1:'+str(active['port'])+'/'+name], 15)
        require(witness.snapshot()['accepted_connections'] == 2, 'operator producer contact count differs')
        entry = invoke('source-before', 'namespace-stat', '--path', '/source.csv', producer=True)
        invoke('ready-before', 'namespace-stat', '--path', '/operator.ready.json', producer=True)
        metadata.private_write(directory/'connection.json', metadata.canonical(
            connection(private, directory, mode, active['port'], producer)))
        args = ('--request-file', directory/'connection.json', '--idempotency-key', prefix+'connection')
        c = invoke('connection-register', 'connection-register', *args)['resource']
        invoke('connection-register-replay', 'connection-register', *args)
        d = definition(c)
        config = {'root': str(root), 'private': str(private), 'raw': str(directory/'raw'),
            'url': 'https://127.0.0.1:'+str(http_port), 'certificate': str(cert), 'token': str(owner),
            'tenant': tenant, 'partner': partner, 'collections_only': True, 'collection_phase': 'ftps-operator',
            'source': c, 'source_counter': str(witness.directory/'counter.json'),
            'definition': d, 'definition_hash': hashlib.sha256(metadata.canonical(d)).hexdigest(),
            'manifest': manifest, 'manifest_hash': hashlib.sha256(metadata.canonical(manifest)).hexdigest(),
            'producer_entry': entry}
        metadata.private_write(directory/'config.json', metadata.canonical(config))
        command(prefix+'browser', ['node', 'scripts/onboarding-exchange-browser.mjs', directory/'config.json'], 150)
        result = metadata.load(directory/'raw/ftps-operator-result.json')
        view = invoke('status', 'workflow-collection-status', '--job-id', result['view']['job']['id'])
        require(metadata.same(view, result['view']), 'operator browser and CLI custody state differ')
        for label, token in (('owner', owner), ('producer', producer_token)):
            metadata.private_write(directory/(label+'.headers'), b'Authorization: Bearer '+read(token, 256)+b'\n')
        for label, name, who, file_id in (('consumer', 'consumer', 'owner', view['inputs'][0]['file_id']),
                ('producer', 'producer', 'producer', entry['file_id']),
                ('ready', 'ready', 'producer', invoke('ready-after', 'namespace-stat', '--path', '/operator.ready.json', producer=True)['file_id'])):
            base = ('/v1/tenants/'+(producer_tenant if who == 'producer' else tenant)
                +'/partners/'+(producer_partner if who == 'producer' else partner))
            status = command(prefix+label+'-readback', ['curl', '-q', '--silent', '--show-error', '--noproxy', '*',
                '--proto', '=https', '--cacert', cert, '--connect-timeout', '3', '--max-time', '10',
                '--max-filesize', '65536', '--header', '@'+str(directory/(who+'.headers')),
                '--output', directory/(name+'.body'), '--write-out', '%{http_code}', config['url']+base+'/files/'+file_id], 15)
            require(status == b'200', 'operator independent HTTPS readback failed')
        invoke('source-after', 'namespace-stat', '--path', '/source.csv', producer=True)
        require(read(directory/'consumer.body') == read(directory/'producer.body') == payload(mode)
            and read(directory/'ready.body') == read(directory/'operator.ready.json'), 'operator independent bytes differ')
        require(witness.snapshot()['accepted_connections'] == 3, 'operator replay reacquired source')
    except Exception:
        try:
            witness.stop()
        except Exception:
            witness.cleanup_failed = True
        raise
    else:
        witness.stop()
    observed = inventory(private, mode)
    return validate(root, private, mode, steps, observed, database), observed


def validate(root, private, mode, steps, observed, database):
    require(mode in ('explicit', 'implicit') and type(database) is str
        and re.fullmatch('freightctl_ftps_[0-9a-f]{32}', database), 'operator mode or fresh database differs')
    dsn = private/'pg-runtime.dsn'
    require(not any(p.is_symlink() for p in (dsn, *dsn.parents)) and dsn.is_file() and dsn.stat().st_mode & 0o077 == 0,
        'operator runtime database reference is linked or not private')
    uri = urlsplit(read(dsn, 4096).decode())
    require(uri.scheme in ('postgres', 'postgresql') and uri.hostname in ('127.0.0.1', '::1')
        and type(uri.port) is int and 1 <= uri.port <= 65535 and uri.path == '/'+database,
        'operator runtime database differs from original parent estate')
    directory, helper = private/('collection-operator-'+mode), private/('source-helper-'+mode)
    require(type(observed) is dict and set(observed) == {'operator', 'source', 'helper_sha256'}
        and set(observed['operator']) == FILES and set(observed['source']) == {'config.json', 'counter.json'},
        'operator original file closure differs')
    require(metadata.same(observed, inventory(private, mode)), 'operator original evidence changed')
    require(not any(p.is_symlink() for parent in (directory, helper) for p in parent.rglob('*')),
        'operator evidence contains a linked file or directory')
    for parent, files in ((directory, FILES), (helper, ('config.json', 'counter.json'))):
        require(not any(p.is_symlink() for p in (parent, *parent.parents))
            and parent.stat().st_mode & 0o077 == 0, 'operator estate not private')
        for name in files:
            path = parent/name
            require(path.stat().st_mode & 0o077 == 0 and path.parent.stat().st_mode & 0o077 == 0,
                'operator original file not private')
    prefix = 'cli-'+mode+'-collection-operator-'
    wanted = {prefix+name for name in COMMANDS if name != 'source'}|{'cli-'+mode+'-collection-source'}
    selected = [s for s in steps if s.get('name', '').startswith(prefix) or s.get('name') == 'cli-'+mode+'-collection-source']
    builds = [s for s in steps if s.get('name') == 'collection-source-build']
    require(len(selected) == len(wanted) and {s['name'] for s in selected} == wanted and len(builds) == 1,
        'operator original command closure differs')
    for step in [*selected, *builds]:
        require(type(step.get('exit_code')) is int and step['exit_code'] == 0, 'operator original command failed')
        for stream in ('stdout', 'stderr'):
            require(digest(private/(step['name']+'.'+stream), 6 << 20) == step[stream+'_sha256'], 'operator process output changed')
    output = lambda name: metadata.load(private/(prefix+name+'.stdout'))
    identity, producer = output('identity'), output('producer-identity')
    require(all(type(v.get('authority_revision')) is int and v['authority_revision'] > 0
        and all(type(v.get(k)) is str and re.fullmatch(UUID, v[k]) for k in ('tenant_id', 'partner_id', 'actor_id'))
        for v in (identity, producer)) and identity['tenant_id'] != producer['tenant_id'], 'operator separate identities differ')
    require(read(directory/'curl.conf', 4096) == curl_config(private, directory/'producer.token', producer),
        'operator stock producer credentials or TLS configuration changed')
    stopped = source.counter(helper/'counter.json', mode, True)
    require(stopped['accepted_connections'] == 3, 'operator stopped source count differs')
    helper_config = {'database': database,
        'dsn_file': str(private/'pg-runtime.dsn'), 'storage': str(private/'custody'),
        'certificate': str(private/'cert.pem'), 'key': str(private/'key.pem'), 'mode': mode}
    require(metadata.same(metadata.load(helper/'config.json'), helper_config), 'operator source fixture detached from exact estate')
    request = connection(private, directory, mode, stopped['port'], producer)
    registered = output('connection-register')
    c = registered['resource']
    require(metadata.same(metadata.load(directory/'connection.json'), request) and registered.get('replayed') is False
        and metadata.same(c, metadata.dispatch.expected_connection_rotation(c, request, 1))
        and metadata.same(output('connection-register-replay'), dict(registered, replayed=True)), 'operator source connection changed')
    for label, token in (('owner', private/'owner.token'), ('producer', directory/'producer.token')):
        require(read(directory/(label+'.headers'), 512) == b'Authorization: Bearer '+read(token, 256)+b'\n',
            'operator readback original identity differs')
    require(read(directory/'source.csv') == read(directory/'consumer.body') == read(directory/'producer.body') == payload(mode)
        and read(directory/'operator.ready.json') == read(directory/'ready.body'), 'operator original byte evidence differs')
    for name in ('source', 'ready'):
        before, after = output(name+'-before'), output(name+'-after')
        require(metadata.same(before, after) and type(before.get('file_id')) is str and re.fullmatch(UUID, before['file_id'])
            and before['path'] == ('/source.csv' if name == 'source' else '/operator.ready.json')
            and before['deleted'] is False and before['kind'] == 'file'
            and before['size_bytes'] == len(read(directory/('source.csv' if name == 'source' else 'operator.ready.json'))),
            'operator producer source revision changed')
    for name in ('consumer', 'producer', 'ready'):
        require(read(private/(prefix+name+'-readback.stdout'), 8) == b'200', 'operator readback HTTP status differs')
    manifest = metadata.load(directory/'operator.ready.json')
    expected_manifest = {'schema_version': 1, 'batch_id': manifest.get('batch_id'),
        'files': [{'name': 'source.csv', 'size_bytes': len(payload(mode)), 'sha256': hashlib.sha256(payload(mode)).hexdigest()}]}
    require(type(expected_manifest['batch_id']) is str and re.fullmatch(UUID, expected_manifest['batch_id'])
        and metadata.same(manifest, expected_manifest), 'operator producer ready manifest differs')
    config = metadata.load(directory/'config.json')
    url = config.get('url')
    require(type(url) is str and re.fullmatch(r'https://127\.0\.0\.1:[1-9][0-9]{0,4}', url)
        and 1 <= int(url.rsplit(':', 1)[1]) <= 65535, 'operator HTTPS endpoint differs')
    d = definition(c)
    expected_config = {'root': str(root), 'private': str(private), 'raw': str(directory/'raw'), 'url': url,
        'certificate': str(private/'cert.pem'), 'token': str(private/'owner.token'),
        'tenant': identity['tenant_id'], 'partner': identity['partner_id'], 'collections_only': True,
        'collection_phase': 'ftps-operator', 'source': c, 'source_counter': str(helper/'counter.json'),
        'definition': d, 'definition_hash': hashlib.sha256(metadata.canonical(d)).hexdigest(), 'manifest': manifest,
        'manifest_hash': hashlib.sha256(metadata.canonical(manifest)).hexdigest(), 'producer_entry': output('source-before')}
    require(metadata.same(config, expected_config), 'operator browser fixture detached from originals')
    return validate_browser(private, directory, mode, identity, config, output('status'))


def validate_browser(private, directory, mode, identity, config, final):
    result = metadata.load(directory/'raw/ftps-operator-result.json')
    require(set(result) == {'kind', 'state', 'mode', 'preview', 'draft', 'approved', 'job_preview', 'queued', 'worked',
        'view', 'visible', 'counters', 'responses', 'reads', 'audits', 'source_control_connections', 'original_key_replays', 'business_acceptance'}
        and result['kind'] == 'ftps-collection-operator-v1' and result['state'] == 'passed' and result['mode'] == mode
        and metadata.same(result['source_control_connections'], 1) and metadata.same(result['original_key_replays'], 4)
        and result['business_acceptance'] == 'unknown' and metadata.same(result['view'], final), 'operator browser result differs')
    c, d = config['source'], config['definition']
    expected_preview = {'definition': d, 'definition_hash': config['definition_hash'], 'effects': [],
        'collection': {'kind': 'ftps.collect', 'source': d['source'], 'connection': c},
        'external_contact': False, 'approval_required': True}
    require(metadata.same(result['preview'], expected_preview), 'operator workflow preview differs')
    draft, approved = result['draft'], result['approved']
    require(draft['id'] == approved['id'] and type(draft['id']) is str and re.fullmatch(UUID, draft['id'])
        and all(metadata.same(w['definition'], d) and w['definition_hash'] == config['definition_hash']
            and metadata.same(w['version'], 1) for w in (draft, approved))
        and draft['state'] == 'draft' and approved['state'] == 'approved'
        and metadata.same(draft['revision'], 1) and metadata.same(approved['revision'], 2)
        and metadata.same(approved['approval_authority'], identity['authority_revision']), 'operator approved workflow differs')
    p = result['job_preview']
    expected_job = {'schema_version': 1, 'workflow': metadata.ref(approved), 'source': d['source'],
        'source_connection': c, 'source_identity': hashlib.sha256((c['id']+':/').encode()).hexdigest(),
        'authority_revision': identity['authority_revision'], 'storage_id': p['definition'].get('storage_id'),
        'namespace_root': '/', 'timeout_seconds': 300, 'effects': []}
    require(type(expected_job['storage_id']) is str and re.fullmatch(UUID, expected_job['storage_id'])
        and metadata.same(p, {'definition': expected_job, 'definition_hash': hashlib.sha256(metadata.canonical(expected_job)).hexdigest(),
            'external_contact': False, 'approval_required': True}), 'operator collection preview differs')
    job, inputs = final['job'], final['inputs']
    require(metadata.same(job['definition'], expected_job) and job['definition_hash'] == p['definition_hash']
        and job['state'] == final['observed_state'] == 'captured' and job['captured'] is True
        and metadata.same(job['attempts'], 1) and metadata.same(job['fence'], 1)
        and metadata.same(job['manifest'], config['manifest']) and job['manifest_hash'] == config['manifest_hash']
        and final['current_authority'] is True and final['business_acceptance'] == 'unknown' and len(inputs) == 1,
        'operator exact captured job differs')
    item = inputs[0]
    require(type(item.get('file_id')) is str and re.fullmatch(UUID, item['file_id'])
        and item['file_id'] == item['object_id'] and item['file_id'] != config['producer_entry']['file_id']
        and item['state'] == 'accepted' and item['source_name'] == 'source.csv'
        and item['sha256'] == config['manifest']['files'][0]['sha256']
        and metadata.same(item['size_bytes'], len(payload(mode))) and item['target_path'] == '/'+item['sha256']+'-source.csv'
        and metadata.same(final['local_states'], [{'input_id': item['id'], 'state': 'published'}]), 'operator immutable input differs')
    queued = {'kind': 'workflow_collection', 'id': job['id'], 'definition_hash': p['definition_hash'], 'state': 'queued', 'revision': 1}
    worked = dict(queued, state='captured', revision=job['revision'])
    require(metadata.same(result['queued'], queued) and metadata.same(result['worked'], worked), 'operator captured receipt differs')
    expected_reads = [
        {'name': 'workflow-preview', 'route': '/workflows/validate', 'method': 'POST', 'status': 200, 'request': {'definition': d}},
        {'name': 'job-preview', 'route': '/workflow-collections/preview', 'method': 'POST', 'status': 200,
            'request': {'workflow': metadata.ref(approved), 'timeout_seconds': 300, 'expected_authority_revision': identity['authority_revision']}},
        *({'name': name, 'route': '/workflow-collections/'+job['id'], 'method': 'GET', 'status': 200, 'request': None}
            for name in ('queued-view', 'captured-view'))]
    require(metadata.same(result['reads'], expected_reads), 'operator original browser read requests differ')
    read_steps = {}
    for observed in expected_reads:
        name, request = observed['name'], observed['request']
        body = read(directory/('raw/'+name+'.body'), 262144)
        require(read(directory/('raw/'+name+'.json'), 262144) == body
            and (metadata.same(metadata.load(directory/('raw/'+name+'.request')), request) if request is not None
                else read(directory/('raw/'+name+'.request'), 32768) == b''), 'operator original browser wire request differs')
        headers = {}
        for line in read(directory/('raw/'+name+'.headers'), 16384).decode().splitlines():
            key, sep, value = line.partition(':')
            key = key.lower()
            require(sep and key not in headers, 'operator original read header duplicated or invalid')
            headers[key] = value.strip()
        require(headers.get('authorization') == 'Bearer '+read(private/'owner.token', 256).decode()
            and (observed['method'] == 'GET' or headers.get('content-type') == 'application/json'), 'operator original read identity differs')
        read_steps[name] = {'name': name+'-wire-response', 'request_method': observed['method'], 'response_status': 200,
            'response_sha256': hashlib.sha256(body).hexdigest()}
    for name, value in (('workflow-preview', expected_preview), ('job-preview', p), ('captured-view', final)):
        require(metadata.same(metadata.load(directory/('raw/'+name+'.body')), value), 'operator original browser response differs')
    initial = metadata.load(directory/'raw/queued-view.body')
    require(initial['job']['id'] == job['id'] and initial['job']['state'] == initial['observed_state'] == 'queued'
        and initial['job']['captured'] is False and metadata.same(initial['job']['attempts'], 0)
        and metadata.same(initial['job']['fence'], 0) and metadata.same(initial['job']['definition'], expected_job)
        and initial['job']['manifest'] is None and initial['job']['manifest_hash'] is None
        and initial['inputs'] == initial['local_states'] == [] and initial['business_acceptance'] == 'unknown'
        and initial['current_authority'] is True, 'operator queue already performed source work')
    targets = ('/workflows/drafts', '/workflows/'+draft['id']+'/1/approve', '/workflow-collections', '/workflow-collections/'+job['id']+'/work')
    selections = ({'expected_version': 0, 'definition': d}, {'definition_hash': draft['definition_hash'], 'expected_revision': 1},
        {'selection': expected_reads[1]['request'], 'definition_hash': p['definition_hash']}, {'definition_hash': p['definition_hash']})
    require(len(result['responses']) == 4, 'operator original-key response count differs')
    keys, wire_steps = [], []
    for index, (name, route, selection, resource) in enumerate(zip(DECISIONS, targets, selections, (draft, approved, queued, worked))):
        response = result['responses'][index]
        label = 'ftps-operator-'+name
        require(set(response) == {'route', 'label', 'observed'} and response['route'] == route
            and response['label'] == label and len(response['observed']) == 2, 'operator original mutation route differs')
        pair_keys = []
        for attempt, observed in enumerate(response['observed']):
            stem = directory/('raw/'+label+'-'+str(attempt))
            body = read(Path(str(stem)+'.json'), 262144)
            require(set(observed) == {'status', 'body', 'selection', 'idempotency_key'} and metadata.same(observed['status'], 200)
                and observed['body'].encode() == body and metadata.same(observed['selection'], selection)
                and metadata.same(metadata.load(Path(str(stem)+'.request')), selection)
                and metadata.same(metadata.load(Path(str(stem)+'.json')), {'resource': resource, 'replayed': bool(attempt)}),
                'operator original mutation or replay changed')
            headers = read(Path(str(stem)+'.headers'), 16384).decode().splitlines()
            parsed = {}
            for line in headers:
                key, sep, value = line.partition(':')
                key = key.lower()
                require(sep and key not in parsed, 'operator duplicate or invalid original header')
                parsed[key] = value.strip()
            key = observed['idempotency_key']
            require(type(key) is str and re.fullmatch('[A-Za-z0-9._:-]{8,128}', key)
                and parsed.get('idempotency-key') == key
                and parsed.get('authorization') == 'Bearer '+read(private/'owner.token', 256).decode()
                and parsed.get('content-type') == 'application/json', 'operator original identity or saved key differs')
            pair_keys.append(key)
            wire_steps.append({'name': label+'-'+str(attempt)+'-wire-response', 'request_method': 'POST',
                'response_status': 200, 'response_sha256': hashlib.sha256(body).hexdigest()})
        require(pair_keys[0] == pair_keys[1] and pair_keys[0] not in keys, 'operator retry key changed or crossed decisions')
        keys.append(pair_keys[0])
    for value, count in zip(result['counters'], (2, 2, 3)):
        require(metadata.same(value, {'schema_version': 1, 'kind': 'freightctl-ftps-source-witness-v1', 'mode': mode,
            'port': int(c['address'].rsplit(':', 1)[1]), 'accepted_connections': count, 'budget_exhausted': False, 'stopped': False}),
            'operator active source observation differs')
    require(len(result['counters']) == 3 and metadata.same(result['audits'], list(AUDITS)), 'operator audit or counter closure differs')
    expected_steps = [{'name': AUDITS[0]+'-axe'}, read_steps['workflow-preview']]
    for index, name in enumerate(DECISIONS):
        if index == 2:
            expected_steps.append(read_steps['job-preview'])
        if index == 3:
            expected_steps.append(read_steps['queued-view'])
        expected_steps.append({'name': AUDITS[index+1]+'-axe'})
        expected_steps.extend(wire_steps[index*2:index*2+2])
        expected_steps.append({'name': 'ftps-operator-'+name+'-original-key-recovery'})
    expected_steps.extend([read_steps['captured-view'], {'name': AUDITS[5]+'-axe'}])
    summary = metadata.load(directory/'raw/onboarding-exchange-browser.json')
    require(summary.get('state') == 'passed' and not summary.get('failure')
        and metadata.same(summary.get('steps'), expected_steps) and summary.get('runtime_errors') == summary.get('external_egress') == []
        and summary.get('model_started') is False and summary.get('production_activated') is False
        and type(summary.get('browser_version')) is str and re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', summary['browser_version'])
        and type(summary.get('node_version')) is str and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', summary['node_version']),
        'operator actual Chrome runtime record differs')
    for name in AUDITS:
        audit = metadata.load(directory/('raw/'+name+'-axe.json'))
        require(audit.get('violations') == [] and type(audit.get('passes')) is int and audit['passes'] > 0,
            'operator actual accessibility audit failed or missing')
    screenshot = read(directory/'raw/onboarding-exchange-review.png', 6 << 20)
    require(len(screenshot) >= 100 and screenshot.startswith(b'\x89PNG\r\n\x1a\n'), 'operator actual screenshot missing')
    visible = result['visible']
    require(type(visible) is str and all(v in ' '.join(visible.split()) for v in (c['user']+'@'+c['address'], mode+' FTPS',
        c['ftps']['server_name'], c['ftps']['ca_sha256'], 'Local collection only', item['file_id']))
        and not any(v in visible for v in (str(private), 'password_reference', 'ca_reference',
            read(private/'owner.token', 256).decode(), read(directory/'producer.token', 256).decode())),
        'operator rendered source, custody identity or privacy differs')
    return {'state': 'passed', 'browser_phases': 1, 'accessibility_audits': 6, 'original_key_replays': 4,
        'source_control_connections': 1, 'captured_files': 1, 'bytes': len(payload(mode)),
        'source_unchanged': True, 'source_kind': 'native-freightctl', 'business_acceptance': 'unknown'}
