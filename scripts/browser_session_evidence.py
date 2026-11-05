"""Reopen private cookie and independent HTTPS session evidence, never secrets in reports."""
from datetime import datetime
import hashlib
import hmac
import re

import ftps_collection_metadata as metadata
from ftps_cli_governance import read, require

ERROR = 'browser session evidence differs'
REASONS = frozenset(('cookie-envelope', 'cookie-scope', 'cookie-expiry', 'envelope', 'identity',
    'state', 'expiry', 'csrf', 'limits', 'probe-headers', 'probe-request', 'headers', 'wire-cookie',
    'wire-fetch-site', 'wire-origin', 'wire-csrf', 'wire-method', 'unrecognized-proof'))
FILES = frozenset(('raw/browser-session-cookie.json',
    *('raw/'+name+'.'+suffix for name in ('session-identity', 'session-current')
        for suffix in ('headers', 'request', 'json'))))
UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'


def message(reason):
    return ERROR+':'+(reason if type(reason) is str and reason in REASONS else 'unrecognized-proof')


def check(value, reason):
    require(value, message(reason))


def headers(path):
    value = {}
    for line in read(path, 16384).decode().splitlines():
        key, sep, item = line.partition(':')
        key = key.lower()
        check(sep and re.fullmatch('[a-z0-9-]+', key) and key not in value
            and not any(ord(c) < 32 or ord(c) == 127 for c in item), 'headers')
        value[key] = item.strip()
    return value


def validate_headers(value, proof, method, url):
    check('authorization' not in value and value.get('cookie') == proof['cookie'], 'wire-cookie')
    check(value.get('sec-fetch-site') == 'same-origin', 'wire-fetch-site')
    if method == 'POST':
        check(value.get('origin') == url and value.get('content-type') == 'application/json', 'wire-origin')
        check(value.get('x-csrf-token') == proof['csrf'], 'wire-csrf')
    else:
        check(method == 'GET' and 'x-csrf-token' not in value, 'wire-method')
        check(value.get('origin') in (None, url), 'wire-origin')


def validate(directory, config, identity):
    cookie = metadata.load(directory/'raw/browser-session-cookie.json')
    check(set(cookie) == {'kind', 'name', 'value', 'domain', 'path', 'secure', 'http_only',
        'same_site', 'expires_unix_ms', 'observed_unix_ms'}
        and cookie['kind'] == 'freightctl-browser-session-cookie-v1'
        and cookie['name'] == '__Host-freightctl-session' and cookie['domain'] == '127.0.0.1'
        and cookie['path'] == '/' and cookie['secure'] is True and cookie['http_only'] is True
        and cookie['same_site'] == 'Strict' and type(cookie['value']) is str, 'cookie-envelope')
    parts = cookie['value'].split('.')
    check(len(parts) == 3 and all(type(config.get(k)) is str and re.fullmatch(UUID, config[k])
        and config[k] == identity[k+'_id'] for k in ('tenant', 'partner'))
        and parts[:2] == [config['tenant'], config['partner']]
        and re.fullmatch('[0-9a-f]{64}', parts[2]), 'cookie-scope')
    observed, expires = cookie['observed_unix_ms'], cookie['expires_unix_ms']
    check(type(observed) is int and type(expires) is int and observed > 0
        and 0 < expires-observed <= 600000, 'cookie-expiry')
    current = metadata.load(directory/'raw/session-current.json')
    check(set(current) == {'identity', 'session', 'csrf_token', 'replayed', 'limits'}
        and current['replayed'] is False, 'envelope')
    check(metadata.same(current['identity'], identity)
        and metadata.same(metadata.load(directory/'raw/session-identity.json'), identity), 'identity')
    session = current['session']
    check(set(session) == {'id', 'expires_at', 'state'} and type(session['id']) is str
        and re.fullmatch(UUID, session['id']) and session['state'] == 'active'
        and type(session['expires_at']) is str
        and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z', session['expires_at']), 'state')
    try:
        api_expires = int(datetime.fromisoformat(session['expires_at'].replace('Z', '+00:00')).timestamp()*1000)
    except (ValueError, OverflowError):
        raise ValueError(message('expiry')) from None
    check(abs(api_expires-expires) <= 2000 and 0 < api_expires-observed <= 600000, 'expiry')
    # Independent qualification derivation: production crypto stays in internal/crypto.
    csrf = hmac.new(parts[2].encode(), b'freightctl.browser.csrf.v1', hashlib.sha256).hexdigest()
    check(type(current['csrf_token']) is str and hmac.compare_digest(current['csrf_token'], csrf), 'csrf')
    limits = current['limits']
    check(set(limits) == {'max_file_bytes', 'min_chunk_bytes', 'max_chunk_bytes', 'max_upload_chunks'}
        and all(type(v) is int and v > 0 for v in limits.values())
        and limits['min_chunk_bytes'] == 64 << 10 and limits['max_chunk_bytes'] == 8 << 20
        and limits['max_upload_chunks'] == 4096, 'limits')
    proof = {'cookie': cookie['name']+'='+cookie['value'], 'csrf': csrf,
        'secrets': [cookie['value'], parts[2], csrf], 'steps': []}
    for name in ('session-identity', 'session-current'):
        value = headers(directory/('raw/'+name+'.headers'))
        check(set(value) == {'cookie', 'origin', 'sec-fetch-site'} and value['origin'] == config['url'], 'probe-headers')
        check(read(directory/('raw/'+name+'.request'), 32768) == b'', 'probe-request')
        validate_headers(value, proof, 'GET', config['url'])
        body = read(directory/('raw/'+name+'.json'), 262144)
        proof['steps'].append({'name': name+'-wire-response', 'request_method': 'GET',
            'response_status': 200, 'response_sha256': hashlib.sha256(body).hexdigest()})
    return proof
