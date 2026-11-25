"""Read-only probes and reversible credential lifecycle. Never print response bodies."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import fnmatch
from importlib.resources import files
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
from urllib.error import URLError
from urllib.parse import quote, urlparse

META = '_vault_lifecycle'
BOOTSTRAP = {'VAULT_SYNC_DEVICE_TOKEN', 'VAULT_SYNC_ENCRYPTION_KEY'}
STATES = {'ok', 'invalid', 'expired', 'no_balance', 'unknown'}


def now():
    return datetime.now(timezone.utc).isoformat()


def masked(value):
    value = str(value)
    return value[:4] + '…' + value[-4:] if len(value) > 8 else '***'


def path_id(group, service, name):
    return json.dumps([group, service, name], ensure_ascii=False, separators=(',', ':'))


def label(path):
    return '/'.join(path)


def backup(vault):
    directory = Path(vault.VAULT_DIR)/'backups'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    dest = directory/('vault-'+uuid.uuid4().hex+'.json')
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out, open(vault.VAULT_FILE, 'rb') as src:
        shutil.copyfileobj(src, out)
        out.flush()
        os.fsync(out.fileno())
    return dest


def field_value(data, path):
    for part in path.split('.'):
        if not isinstance(data, dict) or part not in data:
            return False, None
        data = data[part]
    return True, data


def classify(probe, code, body):
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        data = None
    # Transport / WAF / rate-limit failures must never authorize deletion.
    if code == 429 or code >= 500 or 'cloudflare' in body.lower() or '<html' in body.lower():
        return 'unknown', 'rate limit, network or gateway response'
    for rule in probe.get('rules', []):
        if code not in rule['http']:
            continue
        if rule.get('contains') and not any(s.lower() in body.lower() for s in rule['contains']):
            continue
        if 'field' in rule:
            exists, value = field_value(data, rule['field'])
            if not exists or ('equals' in rule and value != rule['equals']):
                continue
        status = rule['status']
        if status not in STATES:
            raise ValueError('Unsupported probe status')
        return status, f'probe rule: {status} (HTTP {code})'
    return 'unknown', f'unrecognized response (HTTP {code})'


def request(probe, value):
    """Use curl's system trust store; keep auth/URL secrets off argv and suppress raw errors."""
    url = probe['url'].replace('{key}', quote(value, safe=''))
    parsed = urlparse(url)
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'):
        raise ValueError('Probe requires HTTPS (or local test server)')
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; ai-vault/0.2)', 'Accept': 'application/json'}
    headers.update({k: v.replace('{key}', value) for k,v in probe.get('headers', {}).items()})
    method = probe.get('method', 'GET')
    if method not in {'GET', 'POST'}:
        raise ValueError('Unsupported probe method')
    config = ['url = ' + json.dumps(url), 'request = ' + json.dumps(method)]
    config += ['header = ' + json.dumps(k + ': ' + v) for k,v in headers.items()]
    if probe.get('body'):
        config.append('data = ' + json.dumps(probe['body']))
    command = ['curl', '-q', '--silent', '--connect-timeout', '5', '--max-time', '12',
               '--max-filesize', '1048576', '--config', '-', '--write-out', '\n%{http_code}']
    if parsed.hostname == '127.0.0.1':
        command += ['--noproxy', '127.0.0.1']
    result = subprocess.run(command, input='\n'.join(config)+'\n', text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise OSError('Probe connection failed')
    body, _, status = result.stdout.rpartition('\n')
    return int(status), body


def check(vault, group=None, service=None, probes_path=None):
    probes = json.loads(Path(probes_path).read_text() if probes_path else files('ai_vault_data').joinpath('probes.json').read_text())
    data = vault.load_vault()
    results, started = [], {}
    for g,s,n,entry in vault.iter_entries(data):
        if n in BOOTSTRAP or (group and g != group) or (service and s != service):
            continue
        value = str(entry['value'])
        probe = next((p for p in probes if any(fnmatch.fnmatchcase(s.lower(), alias) for alias in p['services']) and
                      any(fnmatch.fnmatchcase(n.upper(), pattern) for pattern in p['keys']) and
                      (not p.get('prefixes') or any(value.startswith(prefix) for prefix in p['prefixes']))), None)
        # An OpenAI-compatible relay key is not an official OpenAI credential.
        # Never infer invalidity by sending it to a different provider.
        mismatched_base = False
        if probe:
            endpoint_host = urlparse(probe['url']).hostname
            bases = [str(e.get('value', '')) for key,e in data[g][s].items()
                     if isinstance(e,dict) and key.upper().endswith(('BASE_URL', 'BASEURL'))]
            mismatched_base = any(urlparse(base).hostname != endpoint_host for base in bases)
            if mismatched_base:
                probe = None
        status, reason = 'unknown', 'no matching read-only probe'
        if mismatched_base:
            reason = 'configured base URL differs from built-in provider; custom probe required'
        if probe:
            bucket = probe.get('id', s.lower())
            delay = 1 - (time.monotonic() - started.get(bucket, -100))
            if delay > 0:
                time.sleep(delay)
            try:
                status, reason = classify(probe, *request(probe, value))
            except (OSError, URLError, ValueError, subprocess.TimeoutExpired):
                status, reason = 'unknown', 'connection or probe configuration error'
            finally:
                # Keep at least one second between the end and start of requests.
                started[bucket] = time.monotonic()
        checked = now()
        entry.update(status=status, last_checked=checked)
        results.append({'path': [g,s,n], 'key': masked(value), 'status': status, 'reason': reason, 'last_checked': checked})
    if results:
        backup(vault)
        vault.save_vault(data)
    print_table(results, [str(e[3]["value"]) for e in vault.iter_entries(data)])
    return results


def print_table(rows, secrets=()):
    def safe(text):
        text = str(text)
        for secret in sorted(set(secrets), key=len, reverse=True):
            if len(secret) > 8:
                text = text.replace(secret, '[redacted]')
        return text
    print('| Location | Key (masked) | Result | Reason | Checked at |')
    print('| --- | --- | --- | --- | --- |')
    for row in rows:
        values = [label(row['path']), row['key'], row['status'], row.get('reason', ''), row.get('last_checked', '')]
        print('| ' + ' | '.join(safe(v).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ') for v in values) + ' |')


def candidates(vault, data):
    return [{'path': [g,s,n], 'key': masked(e['value']), 'status': e['status'], 'last_checked': e.get('last_checked','')}
            for g,s,n,e in vault.iter_entries(data) if n not in BOOTSTRAP and e.get('status') in {'invalid','expired'}]


def confirmed(vault, paths, selected, yes, interactive):
    lookup = {label(p): p for p in paths}
    if len(lookup) != len(paths):
        vault.die('Ambiguous path; rename slash-containing locations before modifying.')
    if yes and not selected:
        vault.die('--yes requires an explicit list of full group/service/name paths.')
    if selected and (len(set(selected)) != len(selected) or not set(selected) <= lookup.keys()):
        vault.die('Selection contains duplicate or ineligible paths; nothing changed.')
    if not yes:
        if not interactive:
            return []
        if not sys.stdin.isatty():
            vault.die('Confirmation requires a real terminal, or --yes with approved paths.')
        chosen = selected or list(lookup)
        print('Selected paths: ' + ', '.join(chosen))
        if input('Type CONFIRM to continue: ').strip() != 'CONFIRM':
            vault.die('Cancelled.')
        return [lookup[p] for p in chosen]
    return [lookup[p] for p in selected]


def remove_entry(data, path):
    g,s,n = path
    del data[g][s][n]
    if not data[g][s]:
        del data[g][s]
    if not data[g]:
        del data[g]


def delete_paths(data, paths, retention_days=30):
    meta = data.setdefault(META, {})
    trash = meta.setdefault('trash', {})
    tombstones = meta.setdefault('tombstones', {})
    for path in paths:
        g,s,n = path
        deletion = now()
        identity = path_id(*path)
        trash[identity] = {'path': path, 'entry': copy.deepcopy(data[g][s][n]), 'deleted_at': deletion,
                           'expires_at': (datetime.now(timezone.utc)+timedelta(days=retention_days)).isoformat()}
        tombstones[identity] = {'path': path, 'deleted_at': deletion}
        remove_entry(data, path)
    # Expired payloads are purged only during an explicitly requested mutation.
    meta['trash'] = {k:v for k,v in trash.items() if v['expires_at'] > now()}


def prune(vault, selected, yes=False, interactive=False):
    data = vault.load_vault()
    rows = candidates(vault, data)
    print_table(rows, [str(e[3]["value"]) for e in vault.iter_entries(data)])
    paths = confirmed(vault, [r['path'] for r in rows], selected, yes, interactive)
    if not paths:
        print('Preview only; no credentials deleted.')
        return
    backup(vault)
    delete_paths(data, paths)
    vault.save_vault(data)
    print(f'Moved {len(paths)} entries to trash (30 days); persistent deletion markers retained.')


def restore(vault, selected, yes=False):
    data = vault.load_vault()
    meta = data.get(META, {})
    trash = meta.get('trash', {})
    eligible = [item['path'] for item in trash.values() if item['expires_at'] > now()]
    paths = confirmed(vault, eligible, selected, yes, True)
    if not paths:
        return
    for g,s,n in paths:
        if n in data.get(g, {}).get(s, {}):
            vault.die('Restore would overwrite an existing entry; nothing changed.')
    backup(vault)
    for path in paths:
        g,s,n = path
        identity = path_id(*path)
        entry = trash.pop(identity)['entry']
        entry.update(_restored_at=now(), status='unknown')
        entry.pop('last_checked', None)
        data.setdefault(g, {}).setdefault(s, {})[n] = entry
        meta.get('tombstones', {}).pop(identity, None)
    vault.save_vault(data)
    print(f'Restored {len(paths)} entries; check again before use.')
