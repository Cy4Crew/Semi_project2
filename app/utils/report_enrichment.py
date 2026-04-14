from __future__ import annotations

import mimetypes
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

URL_RE = re.compile(r'https?://[^\s\'"<>]+', re.I)
DOMAIN_RE = re.compile(r'^(?:[a-z0-9-]+\.)+[a-z]{2,}$', re.I)
IP_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')


def _append_ioc(bucket: dict[tuple[str, str], dict[str, Any]], ioc_type: str, value: Any, source: str, context: str | None = None) -> None:
    normalized = str(value or '').strip()
    if not normalized:
        return
    key_value = normalized if ioc_type in {'registry', 'task', 'service', 'file_path'} else normalized.lower()
    key = (ioc_type, key_value)
    entry = bucket.setdefault(key, {'type': ioc_type, 'value': normalized, 'sources': [], 'contexts': []})
    if source and source not in entry['sources']:
        entry['sources'].append(source)
    if context and context not in entry['contexts']:
        entry['contexts'].append(context)


def normalize_iocs(raw_iocs: dict[str, Any] | None, dynamic_result: dict[str, Any] | None, static_results: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    raw_iocs = raw_iocs or {}
    dynamic_result = dynamic_result or {}
    static_results = static_results or []
    bucket: dict[tuple[str, str], dict[str, Any]] = {}

    for key, ioc_type in [('urls', 'url'), ('domains', 'domain'), ('ips', 'ip'), ('emails', 'email')]:
        for value in raw_iocs.get(key, []) or []:
            _append_ioc(bucket, ioc_type, value, f'aggregate:{key}')
    for value in raw_iocs.get('yara_matches', []) or []:
        _append_ioc(bucket, 'yara_rule', value, 'aggregate:yara')
    for value in raw_iocs.get('suspected_families', []) or []:
        _append_ioc(bucket, 'family', value, 'aggregate:family')
    for value in raw_iocs.get('malware_types', []) or []:
        _append_ioc(bucket, 'malware_type', value, 'aggregate:malware_type')

    for item in static_results:
        member = str(item.get('file') or '')
        iocs = item.get('iocs') or {}
        for key, ioc_type in [('urls', 'url'), ('domains', 'domain'), ('ips', 'ip'), ('emails', 'email')]:
            for value in iocs.get(key, []) or []:
                _append_ioc(bucket, ioc_type, value, f'static:{member}', member)
        for value in item.get('yara_matches', []) or []:
            value = str(value)
            if value.startswith('yara_error:'):
                continue
            _append_ioc(bucket, 'yara_rule', value, f'static:{member}', member)
        for value in item.get('suspected_family', []) or []:
            _append_ioc(bucket, 'family', value, f'static:{member}', member)

    network_trace = dynamic_result.get('network_trace') or {}
    for endpoint in network_trace.get('endpoints', []) or []:
        if isinstance(endpoint, dict):
            url = endpoint.get('url')
            host = endpoint.get('host') or endpoint.get('domain') or endpoint.get('remote_ip') or endpoint.get('ip')
            if url:
                _append_ioc(bucket, 'url', url, 'dynamic:network_trace')
            if host:
                host_str = str(host)
                _append_ioc(bucket, 'ip' if IP_RE.match(host_str) else 'domain', host_str, 'dynamic:network_trace')
        else:
            value = str(endpoint)
            if URL_RE.match(value):
                _append_ioc(bucket, 'url', value, 'dynamic:network_trace')
            else:
                _append_ioc(bucket, 'ip' if IP_RE.match(value) else 'domain', value, 'dynamic:network_trace')

    for change in ((dynamic_result.get('registry_diff') or {}).get('changes') or []):
        if isinstance(change, dict):
            _append_ioc(bucket, 'registry', change.get('key') or change.get('path') or change.get('name'), 'dynamic:registry_diff')
        else:
            _append_ioc(bucket, 'registry', change, 'dynamic:registry_diff')
    for task in ((dynamic_result.get('scheduled_tasks') or {}).get('created') or []):
        if isinstance(task, dict):
            _append_ioc(bucket, 'task', task.get('task_name') or task.get('name') or task.get('path'), 'dynamic:scheduled_tasks')
        else:
            _append_ioc(bucket, 'task', task, 'dynamic:scheduled_tasks')
    for svc in ((dynamic_result.get('services') or {}).get('created') or []):
        if isinstance(svc, dict):
            _append_ioc(bucket, 'service', svc.get('service_name') or svc.get('name') or svc.get('display_name'), 'dynamic:services')
        else:
            _append_ioc(bucket, 'service', svc, 'dynamic:services')

    for dropped in ((dynamic_result.get('filesystem_delta') or {}).get('created_details') or []):
        if not isinstance(dropped, dict):
            continue
        path = dropped.get('path') or dropped.get('name') or dropped.get('file')
        sha256 = dropped.get('sha256') or dropped.get('hash')
        if path:
            _append_ioc(bucket, 'file_path', path, 'dynamic:dropped_file')
        if sha256:
            _append_ioc(bucket, 'file_hash', sha256, 'dynamic:dropped_file', str(path or 'dropped_file'))

    for dump in dynamic_result.get('memory_dumps', []) or []:
        if isinstance(dump, dict):
            _append_ioc(bucket, 'file_path', dump.get('path') or dump.get('name'), 'dynamic:memory_dump')
    for proc in ((dynamic_result.get('process_delta') or {}).get('new_process_tree') or []):
        if isinstance(proc, dict):
            cmdline = str(proc.get('cmdline') or '')
            for match in URL_RE.findall(cmdline):
                _append_ioc(bucket, 'url', match, 'dynamic:process_tree', str(proc.get('name') or proc.get('pid') or 'process'))

    items = sorted(bucket.values(), key=lambda x: (x['type'], x['value'].lower()))
    counts: dict[str, int] = {}
    for item in items:
        counts[item['type']] = counts.get(item['type'], 0) + 1
    return {'items': items, 'counts': counts, 'total': len(items)}


def _guess_category(path: Path) -> str:
    lower = path.name.lower()
    rel = path.as_posix().lower()
    if lower.endswith('.pcap'):
        return 'pcap'
    if lower.endswith('.jsonl'):
        return 'jsonl'
    if lower.endswith('.json'):
        return 'json'
    if lower in {'stdout.txt', 'stderr.txt'}:
        return 'runtime_log'
    if lower.endswith('.dmp') or '/memory/' in rel:
        return 'memory'
    if '/suricata/' in rel:
        return 'suricata'
    if '/extract/' in rel:
        return 'extracted_file'
    return 'artifact'


def build_artifact_manifest(report_id: str, artifact_root: str | Path, dynamic_result: dict[str, Any] | None, evidence_list: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    root = Path(artifact_root)
    files: list[dict[str, Any]] = []
    quick_links: dict[str, str] = {
        'report_json': f'/api/reports/{quote(str(report_id))}/download',
        'evidence_json': f'/api/reports/{quote(str(report_id))}/evidence',
    }
    if root.exists():
        for path in sorted(p for p in root.rglob('*') if p.is_file()):
            rel = path.relative_to(root).as_posix()
            category = _guess_category(path)
            record = {
                'name': path.name,
                'relative_path': rel,
                'size_bytes': path.stat().st_size,
                'category': category,
                'content_type': mimetypes.guess_type(path.name)[0] or 'application/octet-stream',
                'download_url': f'/api/reports/{quote(str(report_id))}/artifacts/file?path={quote(rel)}',
            }
            files.append(record)
            if rel == 'analysis_log.jsonl':
                quick_links['analysis_log'] = record['download_url']
            elif rel == 'stdout.txt':
                quick_links['stdout'] = record['download_url']
            elif rel == 'stderr.txt':
                quick_links['stderr'] = record['download_url']
            elif rel.endswith('.pcap') and 'pcap' not in quick_links:
                quick_links['pcap'] = record['download_url']
            elif rel.endswith('eve.json') and 'suricata_eve' not in quick_links:
                quick_links['suricata_eve'] = record['download_url']

    evidence_links: list[dict[str, Any]] = []
    for entry in (evidence_list or [])[:20]:
        signal = str(entry.get('signal') or '')
        category = str(entry.get('category') or '')
        links: list[dict[str, str]] = []
        if category == 'dynamic':
            for key in ('analysis_log', 'stdout', 'stderr'):
                if key in quick_links:
                    links.append({'label': key, 'url': quick_links[key]})
            if 'network' in signal and 'pcap' in quick_links:
                links.append({'label': 'pcap', 'url': quick_links['pcap']})
        if category in {'archive', 'static'}:
            links.append({'label': 'report_json', 'url': quick_links['report_json']})
        evidence_links.append({'signal': signal, 'category': category, 'links': links})

    return {
        'artifact_root': str(root),
        'quick_links': quick_links,
        'files': files[:200],
        'evidence_links': evidence_links,
        'total_files': len(files),
    }
