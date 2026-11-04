"""Reopen actual Chrome metadata evidence; source bytes remain unqualified."""
import hashlib
import re

import ftps_collection_metadata as metadata
from ftps_cli_governance import read, require

AUDITS = ('ftps-collection-form', 'ftps-collection-preview', 'ftps-collection-selected')
STEP = 'ftps-collection-exact-preview-inspection-without-source-contact'
BROWSER_STAGES = frozenset(('certificate', 'browser-launch', 'context-create', 'login-navigation',
    'login-identity', 'login-credential', 'login-submit', 'files-ready', 'runtime-checks',
    'success-screenshot', 'failure-capture', 'record-write', 'context-close', 'browser-close',
    'complete', 'definition', 'counter-before', 'navigation', 'form', 'form-audit', 'preview-wire',
    'preview-request', 'preview-definition', 'preview-effects', 'preview-source', 'preview-visible',
    'preview-audit', 'inspect-wire', 'inspect-definition', 'inspect-state', 'inspect-visible',
    'selected-audit', 'counter-after', 'response-records', 'result-write'))
FILES = frozenset(('config.json', 'raw/ftps-collection-browser-result.json',
    'raw/onboarding-exchange-browser.json', 'raw/onboarding-exchange-review.png',
    'raw/workflow-preview.body', 'raw/collection-view.body',
    *('raw/'+name+'.'+suffix for name in ('workflow-preview', 'collection-view') for suffix in ('json', 'request', 'headers')),
    *(('raw/'+name+'-axe.json') for name in AUDITS)))

FAILURE_CODES = {
    'collection actual Chrome did not pass': 'chrome-record',
    'collection browser HTTPS address differs': 'url',
    'collection browser accessibility audit missing or failed': 'accessibility',
    'collection browser evidence directory is linked': 'directory-link',
    'collection browser evidence directory is not private': 'directory-permissions',
    'collection browser file closure differs': 'file-closure',
    'collection browser fixture detached from original CLI evidence': 'config-binding',
    'collection browser inventory differs': 'inventory',
    'collection browser mode differs': 'mode',
    'collection browser original HTTP identity differs': 'http-identity',
    'collection browser original HTTP response differs': 'http-response',
    'collection browser original evidence changed': 'evidence-bytes',
    'collection browser original header duplicated or invalid': 'headers',
    'collection browser original source or queued state differs': 'queued-source',
    'collection browser original wire request differs': 'wire-request',
    'collection browser output exposed private references': 'private-reference',
    'collection browser process did not pass': 'process-exit',
    'collection browser process output changed': 'process-bytes',
    'collection browser rendered identity or privacy differs': 'visible-identity',
    'collection browser reviewed metadata or contacts differ': 'result',
    'collection browser screenshot missing': 'screenshot',
}


def failure_code(error):
    return metadata.failure_code(error, FAILURE_CODES)


def command_suffix(name):
    return 'browser' if isinstance(name, str) and re.fullmatch('cli-(explicit|implicit)-collection-browser', name) else None


def safe_observation(value):
    if (type(value) is not dict or type(value.get('mode')) is not str
            or value['mode'] not in ('explicit', 'implicit') or type(value.get('stage')) is not str
            or value['stage'] not in BROWSER_STAGES):
        return None
    if value.get('kind') == 'ftps-collection-browser-progress' and set(value) == {'kind', 'mode', 'stage'}:
        return dict(value)
    if (value.get('kind') != 'ftps-collection-browser-failure'
            or set(value) != {'kind', 'mode', 'stage', 'error_kind', 'source_file', 'source_line'}
            or type(value.get('error_kind')) is not str or value['error_kind'] not in ('assertion', 'timeout', 'syntax', 'other')):
        return None
    file, line = value['source_file'], value['source_line']
    if file is None and line is None:
        return dict(value)
    if type(file) is str and file in ('driver', 'wrapper') and type(line) is int and 1 <= line <= 4000:
        return dict(value)
    return None


def validate(root, private, mode, steps, inventory):
    require(mode in ('explicit', 'implicit'), 'collection browser mode differs')
    directory = private/('collection-browser-'+mode)
    require(isinstance(inventory, dict) and set(inventory) == FILES,
        'collection browser inventory differs')
    require(not any(p.is_symlink() for p in (directory, *directory.parents)),
        'collection browser evidence directory is linked')
    require(all(p.is_dir() and p.stat().st_mode & 0o077 == 0 for p in (directory, directory/'raw')),
        'collection browser evidence directory is not private')
    require({str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file()} == FILES,
        'collection browser file closure differs')
    for name, digest in inventory.items():
        path = directory/name
        require(not any(p.is_symlink() for p in (path, *path.parents))
            and path.stat().st_mode & 0o077 == 0
            and hashlib.sha256(read(path, 6 << 20)).hexdigest() == digest,
            'collection browser original evidence changed')
    name = 'cli-'+mode+'-collection-browser'
    matches = [s for s in steps if s.get('name') == name]
    require(len(matches) == 1 and type(matches[0].get('exit_code')) is int and matches[0]['exit_code'] == 0,
        'collection browser process did not pass')
    for stream in ('stdout', 'stderr'):
        require(hashlib.sha256(read(private/(name+'.'+stream))).hexdigest() == matches[0][stream+'_sha256'],
            'collection browser process output changed')
    output = lambda suffix: metadata.load(private/('cli-'+mode+'-collection-metadata-'+suffix+'.stdout'))
    identity, registered, approved, view, preview = (output(suffix) for suffix in
        ('identity', 'connection-register', 'workflow-approve', 'collection-status', 'workflow-validate'))
    c = registered['resource']
    require(c.get('protocol') == 'ftps' and c['ftps']['mode'] == mode
        and view['job']['state'] == view['observed_state'] == 'queued'
        and view['current_authority'] is True and view['job']['captured'] is False
        and metadata.same(view['job']['attempts'], 0) and metadata.same(view['job']['fence'], 0)
        and view['inputs'] == view['local_states'] == [] and view['business_acceptance'] == 'unknown',
        'collection browser original source or queued state differs')
    config = metadata.load(directory/'config.json')
    url = config.get('url')
    require(isinstance(url, str) and re.fullmatch(r'https://127\.0\.0\.1:[1-9][0-9]{0,4}', url)
        and 1 <= int(url.rsplit(':', 1)[1]) <= 65535, 'collection browser HTTPS address differs')
    expected_config = {'root': str(root), 'private': str(private), 'raw': str(directory/'raw'),
        'url': url, 'certificate': str(private/'cert.pem'), 'token': str(private/'owner.token'),
        'tenant': identity['tenant_id'], 'partner': identity['partner_id'],
        'collections_only': True, 'collection_phase': 'ftps-metadata', 'source': c,
        'source_counter': str(private/('collection-metadata-'+mode)/'source.json'),
        'workflow': approved['resource'], 'view': view}
    require(metadata.same(config, expected_config), 'collection browser fixture detached from original CLI evidence')
    summary = metadata.load(directory/'raw/onboarding-exchange-browser.json')
    wire_steps = {}
    for name, method, request in (('workflow-preview', 'POST', {'definition': approved['resource']['definition']}),
            ('collection-view', 'GET', None)):
        body = read(directory/('raw/'+name+'.body'), 262144)
        require(read(directory/('raw/'+name+'.json'), 262144) == body
            and (metadata.same(metadata.load(directory/('raw/'+name+'.request')), request) if request is not None
                else read(directory/('raw/'+name+'.request'), 32768) == b''), 'collection browser original wire request differs')
        headers = {}
        for line in read(directory/('raw/'+name+'.headers'), 16384).decode().splitlines():
            key, sep, value = line.partition(':')
            key = key.lower()
            require(sep and key not in headers, 'collection browser original header duplicated or invalid')
            headers[key] = value.strip()
        require(headers.get('authorization') == 'Bearer '+read(private/'owner.token', 256).decode()
            and (method == 'GET' or headers.get('content-type') == 'application/json'), 'collection browser original HTTP identity differs')
        wire_steps[name] = {'name': name+'-wire-response', 'request_method': method, 'response_status': 200,
            'response_sha256': hashlib.sha256(body).hexdigest()}
    expected_steps = [{'name': AUDITS[0]+'-axe'}, wire_steps['workflow-preview'], {'name': AUDITS[1]+'-axe'},
        wire_steps['collection-view'], {'name': AUDITS[2]+'-axe'}, {'name': STEP}]
    require(summary.get('state') == 'passed' and not summary.get('failure')
        and summary.get('runtime_errors') == summary.get('external_egress') == []
        and summary.get('model_started') is False and summary.get('production_activated') is False
        and isinstance(summary.get('browser_version'), str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', summary['browser_version'])
        and isinstance(summary.get('node_version'), str) and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', summary['node_version'])
        and metadata.same(summary.get('steps'), expected_steps),
        'collection actual Chrome did not pass')
    for name in AUDITS:
        audit = metadata.load(directory/('raw/'+name+'-axe.json'))
        require(audit.get('violations') == [] and type(audit.get('passes')) is int and audit['passes'] > 0,
            'collection browser accessibility audit missing or failed')
    screenshot = read(directory/'raw/onboarding-exchange-review.png', 6 << 20)
    require(len(screenshot) >= 100 and screenshot.startswith(b'\x89PNG\r\n\x1a\n'),
        'collection browser screenshot missing')
    result = metadata.load(directory/'raw/ftps-collection-browser-result.json')
    active = {'schema_version': 1, 'kind': metadata.dispatch.SPY_KIND, 'accepted_connections': 0,
        'stopped': False, 'budget_exhausted': False}
    expected = {'kind': 'ftps-collection-browser-metadata-v1', 'state': 'passed', 'mode': mode,
        'workflow_preview': preview, 'view': view, 'preview_text': result.get('preview_text'),
        'selected_text': result.get('selected_text'), 'source_counter_before': active, 'source_counter_after': active,
        'source_work_performed': False, 'bytes_qualified': False, 'audits': list(AUDITS),
        'responses': [{'name': 'workflow-preview', 'method': 'POST', 'route': '/workflows/validate',
            'status': 200, 'request': {'definition': approved['resource']['definition']}},
            {'name': 'collection-view', 'method': 'GET', 'route': '/workflow-collections/'+view['job']['id'],
                'status': 200, 'request': None}]}
    require(metadata.same(result, expected), 'collection browser reviewed metadata or contacts differ')
    for name, value in (('workflow-preview', preview), ('collection-view', view)):
        require(metadata.same(metadata.load(directory/('raw/'+name+'.body')), value),
            'collection browser original HTTP response differs')
    forbidden = [str(private), 'password_reference', 'ca_reference', 'Pinned source host',
        read(private/'owner.token', 256).decode(),
        read(private/('collection-metadata-'+mode)/'source-password', 256).decode()]
    terms = (c['user']+'@'+c['address'], mode+' FTPS', c['ftps']['server_name'], c['ftps']['ca_sha256'],
        c['directory'], approved['resource']['definition']['source']['manifest'], 'Local collection only')
    for field in ('preview_text', 'selected_text'):
        visible = result[field]
        require(isinstance(visible, str) and all(term in ' '.join(visible.split()) for term in terms)
            and not any(secret in visible for secret in forbidden), 'collection browser rendered identity or privacy differs')
    public = str(result)+str(summary)
    require(not any(secret in public for secret in forbidden if secret not in ('password_reference', 'ca_reference')),
        'collection browser output exposed private references')
    metadata.dispatch.check_counter(metadata.load(private/('collection-metadata-'+mode)/'source.json'), True)
    return {'state': 'passed', 'browser_phases': 1, 'accessibility_audits': len(AUDITS),
        'source_contacts': 0, 'source_work_performed': False, 'bytes_qualified': False}


def exercise(root, private, mode, http_port, cert, tenant, partner, owner, steps, command, c, approved, view, counter):
    metadata.require_environment(root)
    directory = private/('collection-browser-'+mode)
    directory.mkdir(mode=0o700)
    (directory/'raw').mkdir(mode=0o700)
    config = {'root': str(root), 'private': str(private), 'raw': str(directory/'raw'),
        'url': 'https://127.0.0.1:'+str(http_port), 'certificate': str(cert), 'token': str(owner),
        'tenant': tenant, 'partner': partner, 'collections_only': True, 'collection_phase': 'ftps-metadata',
        'source': c, 'workflow': approved, 'view': view, 'source_counter': str(counter)}
    metadata.private_write(directory/'config.json', metadata.canonical(config))
    command('cli-'+mode+'-collection-browser', ['node', 'scripts/onboarding-exchange-browser.mjs', directory/'config.json'], 150)
    return {str(p.relative_to(directory)): hashlib.sha256(read(p, 6 << 20)).hexdigest()
        for p in sorted(directory.rglob('*')) if p.is_file()}
