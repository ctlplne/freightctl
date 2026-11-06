#!/usr/bin/env python3
"""Prepare synthetic ZIP interoperability inputs; no extraction or execution.

Run only in the native document-container qualification job. This exercises the
stock Python zipfile producer,not Excel or spreadsheet business qualification.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import sys
import zipfile
import zlib


class StreamingOutput:
    def __init__(self):
        self.data = bytearray()

    def write(self, data):
        self.data.extend(data)
        return len(data)

    def flush(self):
        pass


def main():
    if len(sys.argv) != 2:
        raise SystemExit('expected task-owned fixture directory')
    root = Path(sys.argv[1])
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    parts = {
        '[Content_Types].xml': b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        'xl/worksheets/sheet1.xml': b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>',
        'docProps/core.xml': b'<?xml version="1.0" encoding="UTF-8"?><synthetic>0001 &amp; 100.01</synthetic>',
    }
    cases = []
    for method, label in [(zipfile.ZIP_STORED, 'stored'), (zipfile.ZIP_DEFLATED, 'deflated')]:
        for streaming in [False, True]:
            output = StreamingOutput() if streaming else io.BytesIO()
            with zipfile.ZipFile(output, 'w', compression=method, allowZip64=False) as archive:
                archive.comment = b'freightctl synthetic stock-producer input'
                for name, data in parts.items():
                    archive.writestr(name, data)
            body = bytes(output.data) if streaming else output.getvalue()
            name = label + ('-descriptor' if streaming else '-seekable') + '.zip'
            with (root / name).open('xb') as stream:
                stream.write(body)
            os.chmod(root / name, 0o600)
            cases.append({'name': name, 'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body), 'data_descriptor': streaming, 'method': method})
    manifest = {
        'schema_version': 1,
        'producer': {'python': platform.python_version(), 'zipfile': str(zipfile.__file__), 'zlib': zlib.ZLIB_RUNTIME_VERSION},
        'cases': cases,
        'parts': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in parts.items()},
        'claim': 'ZIP member interoperability only;not an XLSX workbook or application custody qualification',
    }
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    os.chmod(root / 'manifest.json', 0o600)


if __name__ == '__main__':
    main()
