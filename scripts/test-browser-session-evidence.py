#!/usr/bin/env python3
"""Synthetic cookie/session/wire forgery contracts. No service or network."""
import copy
from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path
import tempfile
import unittest

import browser_session_evidence as session
import ftps_collection_metadata as metadata


def fixture(directory, config, identity):
    token = hashlib.sha256(b'qualification session fixture, not a credential').hexdigest()
    csrf = hmac.new(token.encode(), b'freightctl.browser.csrf.v1', hashlib.sha256).hexdigest()
    cookie = {'kind': 'freightctl-browser-session-cookie-v1', 'name': '__Host-freightctl-session',
        'value': config['tenant']+'.'+config['partner']+'.'+token, 'domain': '127.0.0.1', 'path': '/',
        'secure': True, 'http_only': True, 'same_site': 'Strict',
        'observed_unix_ms': 1793833200000, 'expires_unix_ms': 1793833800000}
    current = {'identity': copy.deepcopy(identity), 'session': {'id': '30000000-1111-4111-8111-111111111111',
        'expires_at': datetime.fromtimestamp(cookie['expires_unix_ms']/1000, timezone.utc).isoformat().replace('+00:00', 'Z'),
        'state': 'active'}, 'csrf_token': csrf, 'replayed': False,
        'limits': {'min_chunk_bytes': 64 << 10, 'max_chunk_bytes': 8 << 20, 'max_file_bytes': 1 << 30, 'max_upload_chunks': 4096}}
    metadata.private_write(directory/'raw/browser-session-cookie.json', metadata.canonical(cookie))
    base = 'cookie: '+cookie['name']+'='+cookie['value']+'\norigin: '+config['url']+'\nsec-fetch-site: same-origin\n'
    records = []
    for name, value in (('session-identity', identity), ('session-current', current)):
        body = metadata.canonical(value)
        for suffix, data in (('json', body), ('request', b''), ('headers', base.encode())):
            metadata.private_write(directory/('raw/'+name+'.'+suffix), data)
        records.append({'name': name+'-wire-response', 'request_method': 'GET', 'response_status': 200,
            'response_sha256': hashlib.sha256(body).hexdigest()})
    return {'GET': base.encode(), 'POST': (base+'content-type: application/json\nx-csrf-token: '+csrf+'\n').encode()}, records


class SessionContracts(unittest.TestCase):
    def test_every_subreason_is_fixed_and_exception_or_unknown_reason_stays_private(self):
        import ftps_collection_browser as browser
        for reason in session.REASONS:
            with self.assertRaises(ValueError) as caught:
                session.check(False, reason)
            self.assertEqual(browser.failure_code(caught.exception), 'session-'+reason)
            self.assertEqual(browser.failure_code(ValueError(str(caught.exception)+' private-canary')), 'unrecognized-evidence')
        with self.assertRaises(ValueError) as caught:
            session.check(False, '/private/credential-canary')
        self.assertEqual(browser.failure_code(caught.exception), 'session-unrecognized-proof')
        self.assertNotIn('credential-canary', str(caught.exception))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='freightctl-session-contract-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        (self.directory/'raw').mkdir(mode=0o700)
        self.identity = {'tenant_id': '10000000-1111-4111-8111-111111111111',
            'partner_id': '10000001-1111-4111-8111-111111111111', 'actor_id': '10000002-1111-4111-8111-111111111111',
            'authority_revision': 3, 'permissions': ['read', 'write']}
        self.config = {'url': 'https://127.0.0.1:49152', 'tenant': self.identity['tenant_id'], 'partner': self.identity['partner_id']}
        self.headers, self.steps = fixture(self.directory, self.config, self.identity)

    def check(self):
        return session.validate(self.directory, self.config, self.identity)

    def test_original_cookie_readback_and_independent_csrf_binding(self):
        proof = self.check()
        self.assertEqual(proof['steps'], self.steps)
        for method, data in self.headers.items():
            path = self.directory/'original.headers'
            path.write_bytes(data)
            session.validate_headers(session.headers(path), proof, method, self.config['url'])

    def test_rehashed_cookie_flags_identity_authority_csrf_expiry_and_state_are_refused(self):
        cases = [
            ('browser-session-cookie', lambda v: v.update(secure=False)),
            ('browser-session-cookie', lambda v: v.update(http_only=False)),
            ('browser-session-cookie', lambda v: v.update(same_site='Lax')),
            ('browser-session-cookie', lambda v: v.update(domain='.127.0.0.1')),
            ('browser-session-cookie', lambda v: v.update(value='20000000-1111-4111-8111-111111111111.'+v['value'].split('.', 1)[1])),
            ('browser-session-cookie', lambda v: v.update(expires_unix_ms=v['observed_unix_ms'])),
            ('browser-session-cookie', lambda v: v.update(observed_unix_ms=True)),
            ('session-identity', lambda v: v.update(actor_id='20000002-1111-4111-8111-111111111111')),
            ('session-current', lambda v: v['identity'].update(authority_revision=4)),
            ('session-current', lambda v: v.update(csrf_token='0'*64)),
            ('session-current', lambda v: v['session'].update(state='revoked')),
            ('session-current', lambda v: v['session'].update(expires_at='2026-11-04T00:00:00Z')),
            ('session-current', lambda v: v.update(replayed=True)),
            ('session-current', lambda v: v['limits'].update(max_upload_chunks=True)),
        ]
        for name, change in cases:
            with self.subTest(name=name, change=cases.index((name, change))):
                path = self.directory/('raw/'+name+'.json')
                original = path.read_bytes()
                value = metadata.load(path)
                change(value)
                path.write_bytes(metadata.canonical(value))
                with self.assertRaises(ValueError):
                    self.check()
                path.write_bytes(original)

    def test_original_session_probes_refuse_bearer_substitution_body_or_duplicate_headers(self):
        path = self.directory/'raw/session-current.headers'
        original = path.read_bytes()
        for changed in (original+b'authorization: Bearer other\n', original.replace(b'cookie:', b'other:'),
                original+b'cookie: duplicate\n', original.replace(b'same-origin', b'cross-site')):
            path.write_bytes(changed)
            with self.assertRaises(ValueError):
                self.check()
        path.write_bytes(original)
        (self.directory/'raw/session-current.request').write_bytes(b'{}')
        with self.assertRaises(ValueError):
            self.check()

    def test_mutations_require_exact_cookie_csrf_origin_and_no_bearer(self):
        proof = self.check()
        path = self.directory/'original.headers'
        path.write_bytes(self.headers['POST'])
        original = session.headers(path)
        for update in ({'cookie': proof['cookie']+'changed'}, {'x-csrf-token': '0'*64},
                {'origin': 'https://other.invalid'}, {'authorization': 'Bearer other'}, {'sec-fetch-site': 'none'}):
            with self.assertRaises(ValueError):
                session.validate_headers(dict(original, **update), proof, 'POST', self.config['url'])


if __name__ == '__main__':
    unittest.main()
