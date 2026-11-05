#!/usr/bin/env python3
"""Validate a complete pinned peer-image scan; never print raw scanner fields."""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

SCANNER_VERSION = '0.76.1'
SCANNER_IMAGE = 'aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c'
SEVERITIES = ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
ADVISORY = re.compile(r'(?:CVE-[0-9]{4}-[0-9]{4,12}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
REFUSAL_FUNCTIONS = frozenset(('load', 'timestamp', 'summarize', 'main'))


class InvalidReport(ValueError):
    """Only the fixed refusal category reaches public output."""


def refusal_site(error):
    """Static verifier location only: never exception text, locals or paths."""
    site = None
    frame = error.__traceback__
    while frame is not None:
        code = frame.tb_frame.f_code
        if (code.co_filename == __file__ and code.co_name in REFUSAL_FUNCTIONS
                and 1 <= frame.tb_lineno <= 10000):
            site = {'function': code.co_name, 'line': frame.tb_lineno}
        frame = frame.tb_next
    return site


def require(condition):
    if not condition:
        raise InvalidReport('peer-image-evidence-invalid')


def timestamp(value):
    require(isinstance(value, str) and len(value) <= 40)
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise InvalidReport('peer-image-evidence-invalid') from None
    require(result.tzinfo is not None and result.utcoffset() == timedelta(0))
    return result


def load(path, maximum):
    path = Path(path)
    require(path.is_file() and 0 < path.stat().st_size <= maximum)
    raw = path.read_bytes()
    require(len(raw) <= maximum)

    def unique(pairs):
        output = {}
        for key, value in pairs:
            require(key not in output)
            output[key] = value
        return output

    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: require(False))
    except (ValueError, UnicodeError, RecursionError):
        raise InvalidReport('peer-image-evidence-invalid') from None
    return value, hashlib.sha256(raw).hexdigest()


def payload_file(path):
    """Generated binary data is streamed; its size is measured, never a gate."""
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0)
    return path


def summarize(report, version, image, commit, architecture, now):
    require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit))
    require(architecture in ('amd64', 'arm64'))
    require(isinstance(image, list) and len(image) == 1 and isinstance(image[0], dict))
    image = image[0]
    require(isinstance(image.get('Id'), str) and DIGEST.fullmatch(image['Id']))
    require(image.get('Architecture') == architecture and image.get('Os') == 'linux')
    config = image.get('Config')
    require(isinstance(config, dict) and config.get('User') == '65532:65532')
    labels = config.get('Labels')
    require(isinstance(labels, dict) and labels.get('freightctl.purpose') == 'openpgp-interoperability'
            and labels.get('freightctl.source') == commit)
    require(isinstance(version, dict) and version.get('Version') == SCANNER_VERSION)
    database = version.get('VulnerabilityDB')
    require(isinstance(database, dict) and type(database.get('Version')) is int and database['Version'] == 2)
    updated, next_update, downloaded = (timestamp(database.get(key)) for key in ('UpdatedAt', 'NextUpdate', 'DownloadedAt'))
    require(now - timedelta(hours=24) <= updated <= now + timedelta(minutes=5))
    require(updated < next_update and next_update > now)
    require(updated <= downloaded <= now + timedelta(minutes=5)
            and downloaded >= now - timedelta(hours=24))
    require(isinstance(report, dict) and type(report.get('SchemaVersion')) is int and report['SchemaVersion'] == 2)
    require(report.get('ArtifactType') == 'container_image')
    require(isinstance(report.get('Trivy'), dict) and report['Trivy'].get('Version') == SCANNER_VERSION)
    created = timestamp(report.get('CreatedAt'))
    require(now - timedelta(hours=1) <= created <= now + timedelta(minutes=5) and created >= updated)
    metadata = report.get('Metadata')
    require(isinstance(metadata, dict) and metadata.get('ImageID') == image['Id'])
    platform = metadata.get('ImageConfig')
    require(isinstance(platform, dict) and platform.get('architecture') == architecture and platform.get('os') == 'linux')
    os_info = metadata.get('OS')
    # Trivy's pinned Debian analyzer reports the complete /etc/debian_version
    # line, including point releases. Pin Debian major12, not the spelling12.
    require(isinstance(os_info, dict) and os_info.get('Family') == 'debian'
            and isinstance(os_info.get('Name'), str)
            and re.fullmatch(r'12(?:\.(?:0|[1-9][0-9]{0,4})){0,2}', os_info['Name']))
    require(os_info.get('EOSL', False) is False)
    results = report.get('Results')
    require(isinstance(results, list) and 1 <= len(results) <= 2000)
    counts, packages, classes = Counter({s: 0 for s in SEVERITIES}), Counter(), Counter()
    suppressed, inventory_openpgp, inventory_os = 0, False, False
    advisory_ids = set()
    for result in results:
        require(isinstance(result, dict) and result.get('Class') in ('os-pkgs', 'lang-pkgs'))
        kind = result['Class']
        require(isinstance(result.get('Target'), str) and 0 < len(result['Target']) <= 4096)
        require(isinstance(result.get('Type'), str) and 0 < len(result['Type']) <= 64)
        classes[kind] += 1
        inventory = result.get('Packages', [])
        require(isinstance(inventory, list) and len(inventory) <= 100000)
        packages[kind] += len(inventory)
        for package in inventory:
            require(isinstance(package, dict) and isinstance(package.get('Name'), str)
                    and isinstance(package.get('Version'), str))
            if kind == 'os-pkgs' and result['Type'] == 'debian':
                inventory_os = True
            if kind == 'lang-pkgs' and result['Type'] in ('npm', 'node-pkg') and package['Name'] == 'openpgp' and package['Version'] == '6.3.2':
                inventory_openpgp = True
        modified = result.get('ExperimentalModifiedFindings', [])
        require(isinstance(modified, list) and len(modified) <= 100000)
        suppressed += len(modified)
        vulnerabilities = result.get('Vulnerabilities', [])
        require(isinstance(vulnerabilities, list) and len(vulnerabilities) <= 100000)
        for finding in vulnerabilities:
            require(isinstance(finding, dict) and finding.get('Severity') in SEVERITIES)
            counts[finding['Severity']] += 1
            ident = finding.get('VulnerabilityID')
            require(isinstance(ident, str) and 0 < len(ident) <= 128)
            if ADVISORY.fullmatch(ident):
                advisory_ids.add(ident)
    require(inventory_os and inventory_openpgp)
    blocked = suppressed > 0 or any(counts[s] > 0 for s in ('HIGH', 'CRITICAL', 'UNKNOWN'))
    return {
        'state': 'failed' if blocked else 'passed', 'kind': 'native-peer-image-vulnerabilities',
        'source_commit': commit, 'architecture': architecture, 'image_id': image['Id'],
        'scanner_version': SCANNER_VERSION, 'scanner_image': SCANNER_IMAGE,
        'os_family': 'debian', 'os_version': os_info['Name'],
        'feed_updated_at': updated.isoformat(), 'feed_next_update': next_update.isoformat(),
        'report_created_at': created.isoformat(), 'severities': dict(counts),
        'package_counts': dict(packages), 'result_classes': dict(classes),
        'suppressed_findings': suppressed, 'advisory_ids': sorted(advisory_ids)[:50],
        'additional_advisory_ids': max(0, len(advisory_ids) - 50),
        'scope': 'exact test peer image; OS and discovered libraries; no reachability, protocol, released image or complete product claim',
    }


def main():
    parser = argparse.ArgumentParser()
    for argument in ('report', 'version', 'image', 'feed-database', 'archive', 'commit', 'architecture'):
        parser.add_argument('--' + argument, required=True)
    args = parser.parse_args()
    try:
        report, report_sha = load(args.report, 32 << 20)
        version, version_sha = load(args.version, 1 << 20)
        image, image_sha = load(args.image, 1 << 20)
        result = summarize(report, version, image, args.commit, args.architecture, datetime.now(timezone.utc))
        result.update(report_sha256=report_sha, scanner_version_report_sha256=version_sha, image_inspect_sha256=image_sha)
        for name, filename in (('feed_database', args.feed_database), ('image_archive', args.archive)):
            path = payload_file(filename)
            with path.open('rb') as stream:
                result[name + '_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        print(json.dumps(result, sort_keys=True))
        return 1 if result['state'] == 'failed' else 0
    except (InvalidReport, OSError, TypeError, KeyError, OverflowError, RecursionError) as error:
        print(json.dumps({'state': 'failed', 'reason': 'peer-image-evidence-invalid',
                          'refusal_site': refusal_site(error)}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
