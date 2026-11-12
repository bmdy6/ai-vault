"""在本机加密已授权分组的凭据，并与 Supabase 密文快照安全同步。"""
from __future__ import annotations

import argparse
import base64
import copy
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from typing import Any
from urllib.parse import urlparse
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

TOKEN_KEY = 'VAULT_SYNC_DEVICE_TOKEN'
MASTER_KEY = 'VAULT_SYNC_ENCRYPTION_KEY'
BOOTSTRAP_KEYS = {TOKEN_KEY, MASTER_KEY}
AAD = b'personal-ai-vault:personal-infra:v1'
PAIR_AAD = b'personal-ai-vault:pairing:v1'


class SyncError(Exception):
    """表示可以安全展示给用户的同步失败。"""


def canonical(value: object) -> bytes:
    """将数据稳定编码，避免因为字典顺序变化重复上传。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def encode(value: bytes) -> str:
    """将二进制密文编码成传输格式。"""
    return base64.b64encode(value).decode()


def decode(value: str) -> bytes:
    """严格解析传输中的二进制数据。"""
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise SyncError('密文格式不正确，未写入任何凭据。') from exc


def seal(value: object, key: bytes, aad: bytes = AAD) -> dict[str, object]:
    """使用随机 nonce 和 AES-256-GCM 加密并认证整个快照。"""
    nonce = secrets.token_bytes(12)
    return {'version': 1, 'nonce': encode(nonce), 'ciphertext': encode(AESGCM(key).encrypt(nonce, canonical(value), aad))}


def unseal(envelope: dict[str, Any], key: bytes, aad: bytes = AAD) -> object:
    """验证密文完整性后解密，失败时不暴露内容。"""
    if not isinstance(envelope, dict) or envelope.get('version') != 1 or set(envelope) != {'version', 'nonce', 'ciphertext'}:
        raise SyncError('不支持的加密格式。')
    from cryptography.exceptions import InvalidTag
    try:
        plain = AESGCM(key).decrypt(decode(envelope['nonce']), decode(envelope['ciphertext']), aad)
        return json.loads(plain)
    except (InvalidTag, ValueError, KeyError, TypeError) as exc:
        raise SyncError('解密失败：主密钥不匹配或密文被修改，未导入。') from exc


def load_vault_module(home: Path):
    """Load the bundled CLI storage implementation for this vault directory."""
    script = Path(__file__).with_name("ai_vault.py")
    spec = importlib.util.spec_from_file_location('ai_vault', script)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    module.VAULT_DIR = str(home)
    module.VAULT_FILE = str(home/'vault.json')
    return module


def records_from(data: dict, blocked: set[str], allowed_groups: list[str] | None = None) -> dict[str, dict]:
    """提取已授权分组，排除同步主密钥、设备令牌和暂缓同步项。"""
    records = {}
    entries_by_name = {}
    for group in allowed_groups if allowed_groups is not None else ['personal-infra']:
        services = data.get(group, {})
        if not isinstance(services, dict):
            raise SyncError('本机分组结构不正确：' + group)
        for service, entries in services.items():
            if not isinstance(entries, dict):
                continue
            for name, entry in entries.items():
                if name in BOOTSTRAP_KEYS or name in blocked or not isinstance(entry, dict) or 'value' not in entry:
                    continue
                entries_by_name.setdefault(name, []).append({'group': group, 'service': service, 'entry': copy.deepcopy(entry)})
    for name, entries in entries_by_name.items():
        for record in entries:
            identity = name
            if len(entries) > 1:
                record['key'] = name
                identity = record_identity(record['group'], record['service'], name)
            if identity in records:
                raise SyncError('快照记录标识重复，请先检查：' + name)
            records[identity] = record
    return records


def record_identity(group: str, service: str, name: str) -> str:
    """为跨服务同名配置生成可逆且不含凭据值的记录标识。"""
    return 'path:' + json.dumps([group, service, name], ensure_ascii=False, separators=(',', ':'))


def find_record(vault, data: dict, identity: str, record: dict):
    """按原始路径查找同名配置，普通唯一 Key 仍检查全局归属。"""
    if 'key' not in record:
        return vault.find_entry(data, identity)
    group, service, name = record['group'], record['service'], record['key']
    entry = data.get(group, {}).get(service, {}).get(name)
    return (group, service, entry) if entry is not None else None


def validate_records(value: object, blocked: set[str], allowed_groups: list[str] | None = None) -> dict[str, dict]:
    """兼容旧个人快照，拒绝未授权分组和同步启动凭据导入。"""
    allowed = set(allowed_groups if allowed_groups is not None else ['personal-infra'])
    if not isinstance(value, dict) or value.get('format') not in (1, 2):
        raise SyncError('云端快照格式不受支持，请升级同步工具。')
    scope = value.get('scope')
    if not isinstance(scope, list) or not scope or any(not isinstance(group, str) or not group for group in scope):
        raise SyncError('云端快照范围不正确。')
    if len(scope) != len(set(scope)) or not set(scope) <= allowed:
        raise SyncError('云端快照超出本机已授权范围，请先核对同步配置。')
    if value['format'] == 1 and scope != ['personal-infra']:
        raise SyncError('旧版快照只能包含个人分组。')
    records = value.get('records')
    if not isinstance(records, dict):
        raise SyncError('云端凭据结构不正确。')
    paths = set()
    for name, record in records.items():
        if not isinstance(name, str) or not isinstance(record, dict) or record.get('group') not in scope or not isinstance(record.get('service'), str) or not isinstance(record.get('entry'), dict) or 'value' not in record['entry']:
            raise SyncError('云端快照包含禁止导入的记录。')
        original = record.get('key', name)
        if not isinstance(original, str) or not original or original in BOOTSTRAP_KEYS:
            raise SyncError('云端快照包含禁止导入的记录。')
        path = (record['group'], record['service'], original)
        if path in paths or ('key' in record and (value['format'] != 2 or name != record_identity(*path))):
            raise SyncError('云端快照包含重复或无效的配置路径。')
        paths.add(path)
    return {name: record for name, record in records.items() if record.get('key', name) not in blocked}


def merge_records(local: dict, remote: dict) -> tuple[dict, dict, dict]:
    """合并互不冲突的新增项，同名不同值时拒绝覆盖。"""
    conflicts = sorted(name for name in local.keys() & remote.keys() if local[name] != remote[name])
    if conflicts:
        raise SyncError('存在冲突，未覆盖任何值：' + ', '.join(conflicts) + '；请在真实终端使用 resolve 选择来源。')
    merged = {**remote, **local}
    return merged, {k: remote[k] for k in remote.keys()-local.keys()}, {k: local[k] for k in local.keys()-remote.keys()}


def validate_config(config: dict) -> dict:
    """拒绝非 Supabase 地址和未经授权的同步范围。"""
    parsed = urlparse(config.get('endpoint', ''))
    hosted = parsed.scheme == 'https' and bool(parsed.hostname and parsed.hostname.endswith('.supabase.co'))
    local = parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port is not None
    if (not (hosted or local) or parsed.path != '/functions/v1/vault-sync'
            or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment):
        raise SyncError('需要 Supabase HTTPS 地址或 127.0.0.1 上的本地测试地址。')
    groups = config.get('allowed_groups')
    if not isinstance(groups, list) or not groups or any(not isinstance(group, str) or not group or group in {'version', 'created_at', '*'} for group in groups) or len(groups) != len(set(groups)):
        raise SyncError('同步配置必须明确列出已授权分组。')
    blocked = config.get('blocked_keys', [])
    if not isinstance(blocked, list) or any(not isinstance(key, str) for key in blocked):
        raise SyncError('blocked_keys 必须是名称列表。')
    return config


def config_for(home: Path) -> dict:
    """读取并验证不包含凭据的本机同步配置。"""
    path = home/'cloud-sync.json'
    if not path.exists():
        raise SyncError('本机尚未配对，请先运行 join。')
    return validate_config(json.loads(path.read_text()))


def entry_value(vault, name: str) -> str:
    """从 ai-vault 获取单项运行凭据，不输出明文。"""
    found = vault.find_entry(vault.load_vault(), name)
    if not found:
        raise SyncError('缺少同步启动凭据：' + name)
    return str(found[2]['value'])


class Cloud:
    """通过设备令牌调用只读或追加密文快照接口。"""
    def __init__(self, endpoint: str, token: str, allowed_groups: list[str] | None = None):
        """保存当前进程需要的接口和令牌。"""
        self.endpoint = endpoint
        self.token = token
        self.allowed_groups = list(allowed_groups) if allowed_groups is not None else ['personal-infra']

    def call(self, body: dict) -> dict:
        """通过标准输入传递认证头和请求体，避免凭据进入命令行和日志。"""
        request_config = '\n'.join([
            'url = ' + json.dumps(self.endpoint), 'request = "POST"',
            'header = "Content-Type: application/json"',
            'header = ' + json.dumps('Authorization: Bearer ' + self.token),
            'data = ' + json.dumps(json.dumps(body, separators=(',', ':'))),
        ]) + '\n'
        command = ['curl', '-q', '--silent', '--show-error', '--connect-timeout', '15',
                   '--max-time', '45', '--config', '-', '--write-out', '\n%{http_code}']
        if urlparse(self.endpoint).hostname == '127.0.0.1':
            command.extend(['--noproxy', '127.0.0.1'])
        result = subprocess.run(command, input=request_config, text=True, capture_output=True)
        if result.returncode:
            raise SyncError('云端连接失败，请检查网络；未输出认证信息。')
        raw, _, status = result.stdout.rpartition('\n')
        if status == '409':
            raise SyncError('云端版本已被另一台电脑更新，请重新预览后同步。')
        if status == '401':
            raise SyncError('设备未授权或令牌已失效。')
        if status != '200':
            raise SyncError('云端请求未成功，HTTP ' + status)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SyncError('云端返回格式不正确。') from exc

    def read(self, key: bytes, blocked: set[str]) -> tuple[int, dict]:
        """下载最新快照并在本机校验、解密。"""
        snapshot = self.call({'action': 'read'})['snapshot']
        if snapshot is None:
            return 0, {}
        digest = hashlib.sha256(snapshot['payload']['ciphertext'].encode()).hexdigest()
        if digest != snapshot['ciphertext_sha256']:
            raise SyncError('云端快照摘要校验失败，未导入。')
        records = validate_records(unseal(snapshot['payload'], key), blocked, self.allowed_groups)
        return snapshot['version'], records

    def append(self, records: dict, key: bytes, expected_version: int) -> int:
        """按预期版本追加加密快照，不替换旧版本。"""
        scope = sorted(self.allowed_groups)
        legacy = scope == ['personal-infra'] and all('key' not in record for record in records.values())
        plain = {'format': 1 if legacy else 2, 'scope': scope, 'records': records}
        validate_records(plain, set(), self.allowed_groups)
        payload = seal(plain, key)
        return self.call({'action': 'append', 'expected_version': expected_version, 'entry_count': len(records), 'payload': payload})['version']


def add_records(vault, records: dict) -> int:
    """只新增不存在的 Key，禁止移动或覆盖已有记录。"""
    count = 0
    data = vault.load_vault()
    for name, record in sorted(records.items()):
        existing = find_record(vault, data, name, record)
        if existing:
            if existing != (record['group'], record['service'], record['entry']):
                raise SyncError('本机 Key 已变化，停止导入：' + name)
            continue
        entries = data.setdefault(record['group'], {}).setdefault(record['service'], {})
        entries[record.get('key', name)] = copy.deepcopy(record['entry'])
        count += 1
    if count:
        vault.save_vault(data)
    return count


def sync(home: Path, apply: bool = False) -> dict:
    """同步已授权分组的新增项，并回读云端核验，遇冲突停止。"""
    config = config_for(home)
    vault = load_vault_module(home)
    blocked = set(config.get('blocked_keys', []))
    groups = config['allowed_groups']
    local = records_from(vault.load_vault(), blocked, groups)
    cloud = Cloud(config['endpoint'], entry_value(vault, TOKEN_KEY), groups)
    key = decode(entry_value(vault, MASTER_KEY))
    version, remote = cloud.read(key, blocked)
    # 防止同名 Key 跨分组或服务导入。
    for name, record in remote.items():
        found = find_record(vault, vault.load_vault(), name, record)
        if found and (found[0] != record['group'] or found[1] != record['service']):
            raise SyncError('远端 Key 与本机其他归属冲突：' + name)
    merged, incoming, outgoing = merge_records(local, remote)
    counts = {group: sum(record['group'] == group for record in merged.values()) for group in groups}
    report = {'mode': 'apply' if apply else 'preview', 'version': version, 'entry_count': len(merged), 'entries_by_group': counts, 'add_local': len(incoming), 'add_cloud': len(outgoing), 'blocked_keys': sorted(blocked)}
    if apply:
        if outgoing:
            report['version'] = cloud.append(merged, key, version)
        report['added_local'] = add_records(vault, incoming)
        verified_version, remote_after = cloud.read(key, blocked)
        report['verified'] = records_from(vault.load_vault(), blocked, groups) == merged == remote_after
        report['verified_version'] = verified_version
        if not report['verified']:
            raise SyncError('同步后两边不一致，请重新预览；未覆盖已有值。')
    return report


def require_terminal() -> None:
    """确保覆盖和设备配对等操作由用户在真实终端确认。"""
    if not sys.stdin.isatty():
        raise SyncError('这项操作必须由你在真实终端运行。')


def pairing_key(password: str, salt: bytes) -> bytes:
    """用 scrypt 从配对口令派生独立加密密钥。"""
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())


def install_device(home: Path, config: dict, token: str, master: str) -> None:
    """Install a device in an empty or existing vault without overwriting credentials."""
    validate_config(config)
    if len(decode(master)) != 32 or len(token) < 40 or any(
        c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in token
    ):
        raise SyncError('启动凭据格式不正确。')
    vault = load_vault_module(home)
    config_path = home / 'cloud-sync.json'
    existing = vault.load_vault() if (home / 'vault.json').exists() else {}
    if config_path.exists() or any(vault.find_entry(existing, name) for name in BOOTSTRAP_KEYS):
        raise SyncError('已有同步配置或启动凭据，拒绝覆盖。')
    service = vault.ensure_service(existing, 'personal-infra', 'vault-sync')
    service[TOKEN_KEY] = {'value': token, 'description': '设备访问令牌'}
    service[MASTER_KEY] = {'value': master, 'description': '快照加密主密钥'}
    vault.save_vault(existing)
    fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        f.write('\n')


def init_sync(home: Path, endpoint: str, groups: list[str]) -> None:
    """Generate first-device secrets locally and show only the registration digest."""
    device_id = 'device-' + uuid.uuid4().hex[:16]
    token = secrets.token_urlsafe(32)
    install_device(home, {'endpoint': endpoint, 'device_id': device_id, 'allowed_groups': groups},
                   token, encode(secrets.token_bytes(32)))
    digest = hashlib.sha256(token.encode()).hexdigest()
    print("insert into public.vault_sync_devices (device_id, token_hash) values "
          f"('{device_id}', '{digest}');")


def pair(home: Path, output: Path) -> None:
    """生成有口令保护的新设备配对包，包内不含业务凭据。"""
    require_terminal()
    if output.exists():
        raise SyncError('配对文件已存在，拒绝覆盖。')
    password = getpass.getpass('设置配对口令（至少12个字符，不显示）：')
    if len(password) < 12 or getpass.getpass('再输入一次配对口令：') != password:
        raise SyncError('配对口令太短或两次不一致。')
    config = config_for(home)
    vault = load_vault_module(home)
    token = secrets.token_urlsafe(32)
    device_id = 'device-' + uuid.uuid4().hex[:16]
    cloud = Cloud(config['endpoint'], entry_value(vault, TOKEN_KEY), config['allowed_groups'])
    config['device_id'] = device_id
    material = {'config': config, 'token': token, 'master_key': entry_value(vault, MASTER_KEY)}
    salt = secrets.token_bytes(16)
    bundle = {'format': 1, 'salt': encode(salt), 'encrypted': seal(material, pairing_key(password, salt), PAIR_AAD)}
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(bundle, handle)
            handle.flush()
            os.fsync(handle.fileno())
        cloud.call({'action': 'enroll', 'device_id': device_id, 'token_hash': hashlib.sha256(token.encode()).hexdigest()})
    except Exception:
        output.unlink(missing_ok=True)
        raise
    print('加密配对包已保存。把文件传到新电脑，口令单独传递；不要把包或口令发到聊天里。')


def join(home: Path, bundle_path: Path) -> None:
    """在新电脑解密配对包并新增同步启动凭据，不覆盖原配置。"""
    require_terminal()
    if (home/'cloud-sync.json').exists():
        raise SyncError('这台电脑已有同步配置，拒绝覆盖。')
    bundle = json.loads(bundle_path.read_text())
    if bundle.get('format') != 1:
        raise SyncError('配对包格式不正确。')
    password = getpass.getpass('输入配对口令（不显示）：')
    material = unseal(bundle['encrypted'], pairing_key(password, decode(bundle['salt'])), PAIR_AAD)
    if not isinstance(material, dict):
        raise SyncError('配对包内容不正确。')
    install_device(home, material['config'], material['token'], material['master_key'])
    print('设备已配对。先运行 sync 预览，再运行 sync --apply 导入。')


def resolve(home: Path, name: str, use: str) -> None:
    """由用户在真实终端逐项选择冲突来源，保留云端历史版本。"""
    require_terminal()
    config = config_for(home)
    blocked = set(config.get('blocked_keys', []))
    vault = load_vault_module(home)
    cloud = Cloud(config['endpoint'], entry_value(vault, TOKEN_KEY), config['allowed_groups'])
    key = decode(entry_value(vault, MASTER_KEY))
    version, remote = cloud.read(key, blocked)
    local = records_from(vault.load_vault(), blocked, config['allowed_groups'])
    if name not in local or name not in remote:
        raise SyncError('该 Key 不是两边都存在的冲突项。')
    if 'key' in local[name] or 'key' in remote[name]:
        raise SyncError('跨服务同名配置的冲突需先人工整理原路径，未覆盖任何值。')
    if (local[name]['group'], local[name]['service']) != (remote[name]['group'], remote[name]['service']):
        raise SyncError('Key 所属分组或服务不同，请先人工整理归属。')
    if use == 'local':
        if input('将以本机值更新云端，请输入完整 Key 名确认：').strip() != name:
            raise SyncError('已取消。')
        remote[name] = local[name]
        new_version = cloud.append(remote, key, version)
        print(json.dumps({'resolved': name, 'source': 'local', 'version': new_version}, ensure_ascii=False))
    else:
        if input('将以云端值更新本机，请输入完整 Key 名确认：').strip() != name:
            raise SyncError('已取消。')
        current = vault.load_vault()
        group, service, _ = vault.find_entry(current, name)
        current[group][service][name] = copy.deepcopy(remote[name]['entry'])
        vault.save_vault(current)
        print('本机值已按你的确认更新，再运行 sync 检查。')


def main() -> None:
    """提供预览、执行同步、冲突确认和新设备配对命令。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vault-home', type=Path, default=Path.home()/'.config/ai-vault')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('init-sync', help='生成首台设备凭据和登记 SQL')
    p.add_argument('--endpoint', required=True)
    p.add_argument('--group', action='append', required=True)
    p = sub.add_parser('sync', help='默认只预览；--apply 才同步新增项')
    p.add_argument('--apply', action='store_true')
    p = sub.add_parser('pair', help='在本机生成加密设备配对包')
    p.add_argument('output', type=Path)
    p = sub.add_parser('join', help='在新电脑导入加密配对包')
    p.add_argument('bundle', type=Path)
    p = sub.add_parser('resolve', help='真实终端逐项确认冲突来源')
    p.add_argument('key')
    p.add_argument('--use', choices=['local', 'cloud'], required=True)
    args = parser.parse_args()
    try:
        with load_vault_module(args.vault_home).vault_lock(args.vault_home):
            if args.command == 'init-sync':
                init_sync(args.vault_home, args.endpoint, args.group)
            elif args.command == 'sync':
                print(json.dumps(sync(args.vault_home, args.apply), ensure_ascii=False, indent=2))
            elif args.command == 'pair':
                pair(args.vault_home, args.output)
            elif args.command == 'join':
                join(args.vault_home, args.bundle)
            else:
                resolve(args.vault_home, args.key, args.use)
    except (SyncError, OSError, ValueError, KeyError) as exc:
        if isinstance(exc, SyncError):
            print('同步未完成：' + str(exc), file=sys.stderr)
        else:
            print('同步未完成：无法访问文件或数据格式不正确。', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
