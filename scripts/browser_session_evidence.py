"""Reopen private cookie and independent HTTPS session evidence, never secrets in reports."""
from datetime import datetime
import hashlib
import hmac
import re

import ftps_collection_metadata as metadata
from ftps_cli_governance import read, require

ERROR = 'browser session evidence differs'
FILES = frozenset(('raw/browser-session-cookie.json',
    *('raw/'+name+'.'+suffix for name in ('session-identity', 'session-current')
        for suffix in ('headers', 'request', 'json'))))
UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'


def headers(path):
    value = {}
    for line in read(path, 16384).decode().splitlines():
        key, sep, item = line.partition(':')
        key = key.lower()
        require(sep and re.fullmatch('[a-z0-9-]+', key) and key not in value
            and not any(ord(c) < 32 or ord(c) == 127 for c in item), ERROR)
        value[key] = item.strip()
    return value


def validate_headers(value, proof, method, url):
    require('authorization' not in value and value.get('cookie') == proof['cookie']
        and value.get('sec-fetch-site') == 'same-origin', ERROR)
    if method == 'POST':
        require(value.get('origin') == url and value.get('content-type') == 'application/json'
            and value.get('x-csrf-token') == proof['csrf'], ERROR)
    else:
        require(method == 'GET' and 'x-csrf-token' not in value
            and value.get('origin') in (None, url), ERROR)


def validate(directory, config, identity):
    cookie = metadata.load(directory/'raw/browser-session-cookie.json')
    require(set(cookie) == {'kind', 'name', 'value', 'domain', 'path', 'secure', 'http_only',
        'same_site', 'expires_unix_ms', 'observed_unix_ms'}
        and cookie['kind'] == 'freightctl-browser-session-cookie-v1'
        and cookie['name'] == '__Host-freightctl-session' and cookie['domain'] == '127.0.0.1'
        and cookie['path'] == '/' and cookie['secure'] is True and cookie['http_only'] is True
        and cookie['same_site'] == 'Strict' and type(cookie['value']) is str, ERROR)
    parts = cookie['value'].split('.')
    require(len(parts) == 3 and all(type(config.get(k)) is str and re.fullmatch(UUID, config[k])
        and config[k] == identity[k+'_id'] for k in ('tenant', 'partner'))
        and parts[:2] == [config['tenant'], config['partner']]
        and re.fullmatch('[0-9a-f]{64}', parts[2]), ERROR)
    observed, expires = cookie['observed_unix_ms'], cookie['expires_unix_ms']
    require(type(observed) is int and type(expires) is int and observed > 0
        and 0 < expires-observed <= 600000, ERROR)
    current = metadata.load(directory/'raw/session-current.json')
    require(set(current) == {'identity', 'session', 'csrf_token', 'replayed', 'limits'}
        and metadata.same(current['identity'], identity)
        and metadata.same(metadata.load(directory/'raw/session-identity.json'), identity)
        and current['replayed'] is False, ERROR)
    session = current['session']
    require(set(session) == {'id', 'expires_at', 'state'} and type(session['id']) is str
        and re.fullmatch(UUID, session['id']) and session['state'] == 'active'
        and type(session['expires_at']) is str
        and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z', session['expires_at']), ERROR)
    try:
        api_expires = int(datetime.fromisoformat(session['expires_at'].replace('Z', '+00:00')).timestamp()*1000)
    except (ValueError, OverflowError):
        raise ValueError(ERROR) from None
    require(abs(api_expires-expires) <= 2000 and 0 < api_expires-observed <= 600000, ERROR)
    # Independent qualification derivation: production crypto stays in internal/crypto.
    csrf = hmac.new(parts[2].encode(), b'freightctl.browser.csrf.v1', hashlib.sha256).hexdigest()
    require(type(current['csrf_token']) is str and hmac.compare_digest(current['csrf_token'], csrf), ERROR)
    limits = current['limits']
    require(set(limits) == {'max_file_bytes', 'min_chunk_bytes', 'max_chunk_bytes', 'max_upload_chunks'}
        and all(type(v) is int and v > 0 for v in limits.values())
        and limits['min_chunk_bytes'] == 64 << 10 and limits['max_chunk_bytes'] == 8 << 20
        and limits['max_upload_chunks'] == 4096, ERROR)
    proof = {'cookie': cookie['name']+'='+cookie['value'], 'csrf': csrf,
        'secrets': [cookie['value'], parts[2], csrf], 'steps': []}
    for name in ('session-identity', 'session-current'):
        value = headers(directory/('raw/'+name+'.headers'))
        require(set(value) == {'cookie', 'origin', 'sec-fetch-site'} and value['origin'] == config['url']
            and read(directory/('raw/'+name+'.request'), 32768) == b'', ERROR)
        validate_headers(value, proof, 'GET', config['url'])
        body = read(directory/('raw/'+name+'.json'), 262144)
        proof['steps'].append({'name': name+'-wire-response', 'request_method': 'GET',
            'response_status': 200, 'response_sha256': hashlib.sha256(body).hexdigest()})
    return proof
