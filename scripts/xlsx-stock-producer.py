#!/usr/bin/env python3
"""Qualify one pinned stock producer's dependency closure;prepare synthetic XLSX.

This runs on GitHub's actual ARM/x86 runners,not the shared local workstation.
It neither opens Excel nor executes formulas or follows workbook links.
"""
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import sys
from urllib.request import Request, urlopen

import xlsxwriter


def json_request(url, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = Request(url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'freightctl-native-xlsx-qualification'})
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def main():
    if len(sys.argv) != 2 or xlsxwriter.__version__ != '3.3.1':
        raise SystemExit('exact stock producer and fixture directory required')
    root = Path(sys.argv[1])
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    distribution = metadata.distribution('xlsxwriter')
    if distribution.requires:
        raise SystemExit('producer dependency closure changed;scan every dependency before qualification')
    pypi = json_request('https://pypi.org/pypi/xlsxwriter/3.3.1/json')
    osv = json_request('https://api.osv.dev/v1/query', {'package': {'name': 'xlsxwriter', 'ecosystem': 'PyPI'}, 'version': '3.3.1'})
    if pypi.get('info', {}).get('version') != '3.3.1' or pypi['info'].get('requires_dist'):
        raise SystemExit('release identity or dependency closure differs')
    if not isinstance(pypi.get('vulnerabilities'), list) or not isinstance(osv, dict) or any(k not in {'vulns'} for k in osv) or 'vulns' in osv and not isinstance(osv['vulns'], list):
        raise SystemExit('incomplete vulnerability response;qualification is owed')
    expected_wheel = '8e2c89e59d733fe59e112317218c64fbbc276d90a8c144ebd6f7fa15e7ab184a'
    wheels = [item for item in pypi.get('urls', []) if item.get('filename') == 'xlsxwriter-3.3.1-py3-none-any.whl']
    if len(wheels) != 1 or wheels[0].get('digests', {}).get('sha256') != expected_wheel or wheels[0].get('yanked') is not False:
        raise SystemExit('stock producer wheel identity or release state differs')
    scan = {'schema_version': 1, 'observed_at': datetime.now(timezone.utc).isoformat(), 'ecosystem': 'PyPI', 'name': 'xlsxwriter', 'version': '3.3.1', 'wheel_sha256': expected_wheel, 'dependencies': [], 'pypi': pypi['vulnerabilities'], 'osv': osv.get('vulns', []), 'sources': ['https://pypi.org/pypi/xlsxwriter/3.3.1/json', 'https://api.osv.dev/v1/query']}
    (root / 'producer-security.json').write_text(json.dumps(scan, indent=2) + '\n')
    os.chmod(root / 'producer-security.json', 0o600)
    if scan['pypi'] or scan['osv']:
        raise SystemExit('stock producer has vulnerability findings;see task-owned security evidence')
    cases = []
    labels = ['shared', 'inline', 'rich', 'literal_formula', 'literal_escape', 'serial_1900', 'serial_1904', 'numeric_identifier', 'formula', 'formula_other_sheet', 'external_link', 'fake_leap_day', 'row_limit']
    for label in labels:
        target = root / (label + '.xlsx')
        options = {'strings_to_formulas': False, 'strings_to_urls': False}
        if label == 'inline':
            options['constant_memory'] = True
        if label == 'serial_1904':
            options['date_1904'] = True
        book = xlsxwriter.Workbook(target, options)
        book.set_properties({'title': 'freightctl synthetic format qualification', 'created': datetime(2026, 11, 6)})
        sheet = book.add_worksheet('Records')
        for index, header in enumerate(['account', 'amount', 'day']):
            sheet.write_string(0, index, header)
        rows = 6 if label == 'row_limit' else 1
        date_format = book.add_format({'num_format': 'yyyy-mm-dd'})
        for row in range(1, rows + 1):
            account = '=SUM(1,2)' if label == 'literal_formula' else '_x0041_' if label == 'literal_escape' else '0001'
            if label == 'rich':
                bold = book.add_format({'bold': True})
                sheet.write_rich_string(row, 0, bold, '00', '01')
            elif label == 'numeric_identifier':
                sheet.write_number(row, 0, 1, book.add_format({'num_format': '0000'}))
            else:
                sheet.write_string(row, 0, account)
            sheet.write_number(row, 1, 100.01)
            if label in {'serial_1900', 'serial_1904'}:
                sheet.write_datetime(row, 2, datetime(2026, 10, 28), date_format)
            elif label == 'fake_leap_day':
                sheet.write_number(row, 2, 60, date_format)
            else:
                sheet.write_string(row, 2, '2026-10-28')
        other = book.add_worksheet('Other')
        if label == 'formula_other_sheet':
            other.write_formula(0, 0, '=1+1', None, 2)
        if label == 'formula':
            sheet.write_formula(1, 1, '=1+1', None, 100.01)
        if label == 'external_link':
            sheet.write_url(1, 0, 'https://never-contact.invalid/synthetic')
        book.close()
        os.chmod(target, 0o600)
        body = target.read_bytes()
        cases.append({'name': target.name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()})
    manifest = {'schema_version': 1, 'producer': {'name': 'xlsxwriter', 'version': xlsxwriter.__version__, 'python': platform.python_version()}, 'cases': cases, 'claim': 'stock-producer parser proof only;not Excel,application custody,release or independent adoption'}
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    os.chmod(root / 'manifest.json', 0o600)
    print('Pinned XlsxWriter dependency closure passed both sources;prepared 13 actual native synthetic workbooks.')


if __name__ == '__main__':
    main()
