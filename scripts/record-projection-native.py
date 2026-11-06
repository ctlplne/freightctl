#!/usr/bin/env python3
"""Independent stock-format fixtures/readback for native record processing.

Only synthetic data;no file extraction,formulas,inference,network or transfers.
The receiver verifies format/byte semantics,not application custody or adoption.
"""
import csv
from decimal import Decimal
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import sys
import xml.etree.ElementTree as ET

ROWS = [
    ['0001', '12345678901234567890.12', '2026-10-28'],
    ['0002', '-0.10', '2026-10-29'],
    ['0001', '12345678901234567890.12', '2026-10-28'],
]


def identity(path):
    body = path.read_bytes()
    return {'name': path.name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


def prepare(root):
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    text = io.StringIO(newline='')
    writer = csv.writer(text, lineterminator='\n')
    writer.writerow(['account', 'amount', 'day'])
    writer.writerows(ROWS)
    (root / 'source.csv').write_bytes(text.getvalue().encode())
    # JSON numbers are literal exact decimals,never a Python float round-trip.
    data = '[' + ','.join('{"account":' + json.dumps(row[0]) + ',"amount":' + row[1] + ',"day":' + json.dumps(row[2]) + '}' for row in ROWS) + ']\n'
    (root / 'source.json').write_text(data)
    records = ET.Element('records')
    for row in ROWS:
        record = ET.SubElement(records, 'record')
        for key, value in zip(['account', 'amount', 'day'], row):
            ET.SubElement(record, key).text = value
    (root / 'source.xml').write_bytes(ET.tostring(records, encoding='utf-8', xml_declaration=True))
    (root / 'source.fixed').write_text(''.join(row[0] + row[1].rjust(24) + row[2] + '\r\n' for row in ROWS))
    manifest = {'schema_version': 1, 'python': platform.python_version(), 'element_tree': ET.VERSION, 'inputs': [identity(root / ('source.' + ext)) for ext in ['csv', 'json', 'xml', 'fixed']]}
    (root / 'inputs.json').write_text(json.dumps(manifest, indent=2) + '\n')
    for path in root.iterdir():
        os.chmod(path, 0o600)


def verify(root):
    manifest = json.loads((root / 'outputs' / 'manifest.json').read_text())
    assert manifest['schema_version'] == 1 and len(manifest['outputs']) == 10
    remaining = {(name, kind) for name in ['csv', 'json_records', 'xml_records', 'fixed_width', 'xlsx_records'] for kind in ['csv', 'json_records']}
    for item in manifest['outputs']:
        assert (item['source_kind'], item['output_kind']) in remaining
        remaining.remove((item['source_kind'], item['output_kind']))
        name = item['file']
        assert Path(name).name == name
        path = root / 'outputs' / name
        body = path.read_bytes()
        report = item['report']
        assert report['code'] == 'transformed' and report['output_bytes'] == len(body)
        assert report['output_sha256'] == hashlib.sha256(body).hexdigest()
        expected = ROWS if item['source_kind'] != 'xlsx_records' else [['0001', '100.01', '2026-10-28']]
        assert report['rows'] == len(expected) and report['source']['rows'] == len(expected)
        if item['output_kind'] == 'json_records':
            actual = json.loads(body, parse_int=Decimal, parse_float=Decimal)
            assert len(actual) == len(expected)
            for row, want in zip(actual, expected):
                assert list(row) == ['total', 'account', 'date']
                assert isinstance(row['total'], Decimal) and str(row['total']) == want[1]
                assert row['account'] == want[0] and row['date'] == want[2]
        else:
            reader = csv.reader(io.StringIO(body.decode(), newline=''))
            actual = list(reader)
            assert actual[0] == ['total', 'account', 'date']
            assert actual[1:] == [[row[1], row[0], row[2]] for row in expected]
    assert not remaining
    print('Independent Python JSON/Decimal and CSV receiver verified 10 exact outputs,five source formats,ordered duplicates and unchanged money/identifier/date values.')


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in {'prepare', 'verify'}:
        raise SystemExit('expected prepare|verify and task-owned directory')
    os.umask(0o077)
    (prepare if sys.argv[1] == 'prepare' else verify)(Path(sys.argv[2]))
