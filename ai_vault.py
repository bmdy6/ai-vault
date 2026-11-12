#!/usr/bin/env python3
"""Personal credential CLI. Values are stored in a private local JSON file."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import getpass
import json
import os
import sys
import tempfile
from pathlib import Path

VAULT_DIR = os.path.expanduser("~/.config/ai-vault")
VAULT_FILE = os.path.join(VAULT_DIR, "vault.json")


# ---------- 存储（明文）----------

def load_vault() -> dict:
    if not os.path.exists(VAULT_FILE):
        die(f"仓库未初始化。请先运行：python {__file__} init")
    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_vault(data: dict) -> None:
    home = Path(VAULT_DIR)
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=home, encoding="utf-8", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            os.replace(temporary, VAULT_FILE)
        finally:
            temporary.unlink(missing_ok=True)


@contextmanager
def vault_lock(home: Path):
    """Keep the two CLI entry points from racing on the same local store."""
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(home / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            die("Vault 正在使用，请等当前操作完成后重试。")
        yield
    finally:
        os.close(fd)


def empty_vault() -> dict:
    return {}



# ---------- 工具 ----------

def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)


def iter_entries(data: dict):
    """Yield (group, service, key, entry) from the grouped vault."""
    for group, services in data.items():
        if group in {"version", "created_at"} or not isinstance(services, dict):
            continue
        for service, entries in services.items():
            if not isinstance(entries, dict):
                continue
            for key, entry in entries.items():
                if isinstance(entry, dict) and "value" in entry:
                    yield group, service, key, entry


def find_entry(data: dict, key: str) -> tuple[str, str, dict] | None:
    for group, service, entry_key, entry in iter_entries(data):
        if entry_key == key:
            return group, service, entry
    return None


def entry_count(data: dict) -> int:
    return sum(1 for _ in iter_entries(data))


def ensure_service(data: dict, group: str, service: str) -> dict:
    return data.setdefault(group, {}).setdefault(service, {})


def mask(value: str) -> str:
    """Never reveal part of a credential in listing or confirmation output."""
    return "***" if value else "(空)"


# ---------- 命令实现 ----------

def cmd_init(args) -> None:
    if os.path.exists(VAULT_FILE):
        if not args.force:
            die(f"仓库已存在：{VAULT_FILE}\n如要重置，加 --force（会清空所有配置！）")
        # 清空是破坏性操作：必须真实终端交互确认（AI 通过 Bash 调用无 tty，会被挡住）
        if not sys.stdin.isatty():
            die("❌ init --force 必须在真实终端交互执行（AI 无权清空 vault）。请你在终端手动运行此命令。")
        confirm = input("⚠️ 将清空整个 vault！输入 REPLACE 确认：").strip()
        if confirm != "REPLACE":
            die("已取消（需输入 REPLACE 确认）")
    save_vault(empty_vault())
    print(f"✅ 仓库已初始化：{VAULT_FILE}（明文，权限 0600）")


def cmd_list(args) -> None:
    data = load_vault()
    entries = [entry for entry in iter_entries(data)
               if entry[2] not in {"VAULT_SYNC_DEVICE_TOKEN", "VAULT_SYNC_ENCRYPTION_KEY"}]
    service_filter = args.service or args.category
    group_filter = args.group or args.project
    if service_filter:
        entries = [e for e in entries if e[1] == service_filter]
    if group_filter:
        entries = [e for e in entries if e[0] == group_filter]
    if not entries:
        print("（仓库为空或无匹配项）")
        return
    print(f"📋 ai-vault 共 {len(entries)} 条配置（value 已脱敏）：\n")
    current = None
    for group, service, key, entry in sorted(entries):
        if (group, service) != current:
            print(f"  [{group} / {service}]")
            current = (group, service)
        print(f"    {key:36s} {mask(str(entry.get('value', '')))}")
        if entry.get("description"):
            print(f"    {'':36s} {entry['description']}")
    print(f"\n共 {len(entries)} 条。取明文：ai-vault get <key>")


def cmd_get(args) -> None:
    data = load_vault()
    found = find_entry(data, args.key)
    if not found:
        die(f"❌ 找不到 key：{args.key}\n用 list 查看所有可用 key。")
    group, service, entry = found
    if args.with_meta:
        safe_entry = {
            "group": group,
            "service": service,
            "description": entry.get("description", ""),
            "value": mask(str(entry.get("value", ""))),
        }
        print(json.dumps(safe_entry, ensure_ascii=False, indent=2))
    else:
        print(entry.get("value", ""))


def cmd_set(args) -> None:
    data = load_vault()
    existing = find_entry(data, args.key)
    if existing:
        entry = existing[2]
        print(f"⚠️ key 已存在：{args.key}", file=sys.stderr)
        print(f"   当前值：{mask(str(entry.get('value','')))}", file=sys.stderr)
        print("   修改已有配置请在真实终端手动执行：", file=sys.stderr)
        print(f"   ai-vault update {args.key}", file=sys.stderr)
        die("❌ 已拒绝修改已有配置。")
    group = args.group or args.project or "personal-infra"
    service = args.service or args.category or "general"
    ensure_service(data, group, service)[args.key] = {
        "value": args.value,
        "description": args.description or "",
    }
    save_vault(data)
    print(f"✅ 新增：{args.key} = {mask(args.value)}  [{group}/{service}]")


def cmd_update(args) -> None:
    """更新已存在 key 的值——只能由用户在真实终端手动跑，强制交互确认。"""
    data = load_vault()
    found = find_entry(data, args.key)
    if not found:
        die(f"❌ 找不到 key：{args.key}")
    entry = found[2]
    print(f"⚠️ 将修改已有配置：{args.key}", file=sys.stderr)
    print(f"   当前值：{mask(str(entry.get('value','')))}", file=sys.stderr)
    print(f"   新值：  {mask(args.value)}", file=sys.stderr)
    print(file=sys.stderr)
    if not sys.stdin.isatty():
        die("❌ update 必须在真实终端交互执行。请你在终端手动运行此命令。")
    confirm = input("\n确认修改？输入完整 key 名确认：").strip()
    if confirm != args.key:
        die("已取消（输入与 key 名不符）")
    entry["value"] = args.value
    save_vault(data)
    print(f"✅ 已更新：{args.key}")


def cmd_delete(args) -> None:
    """删除——只能由用户在真实终端手动跑，强制交互确认。"""
    data = load_vault()
    found = find_entry(data, args.key)
    if not found:
        die(f"❌ 找不到 key：{args.key}")
    group, service, entry = found
    print(f"⚠️ 将删除配置：{args.key}（{entry.get('description','')}）", file=sys.stderr)
    if not sys.stdin.isatty():
        die("❌ delete 必须在真实终端交互执行。请你在终端手动运行此命令。")
    confirm = input("\n确认删除？输入完整 key 名确认：").strip()
    if confirm != args.key:
        die("已取消（输入与 key 名不符）")
    del data[group][service][args.key]
    if not data[group][service]:
        del data[group][service]
    if not data[group]:
        del data[group]
    save_vault(data)
    print(f"✅ 已删除：{args.key}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vault-home", type=Path, default=Path.home() / ".config/ai-vault")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="首次初始化仓库")
    p_init.add_argument("--force", action="store_true", help="重置（清空）")
    p_init.set_defaults(func=cmd_init)

    p_list = sub.add_parser("list", help="按归属和服务列出 key（脱敏显示 value）")
    p_list.add_argument("--group", default=None)
    p_list.add_argument("--service", default=None)
    p_list.add_argument("--category", default=None, help="--service 的旧别名")
    p_list.add_argument("--project", default=None, help="--group 的旧别名")
    p_list.set_defaults(func=cmd_list)

    p_get = sub.add_parser("get", help="取某个 key 的明文值")
    p_get.add_argument("key")
    p_get.add_argument("--project", help="兼容旧命令，已不参与权限判断")
    p_get.add_argument("--with-meta", action="store_true")
    p_get.set_defaults(func=cmd_get)

    p_set = sub.add_parser("set", help="新增配置（已存在的 key 会被拒绝）")
    p_set.add_argument("key")
    p_set.add_argument("--stdin", action="store_true", help="从标准输入读取值")
    p_set.add_argument("--description", default=None)
    p_set.add_argument("--category", default=None, help="兼容旧命令；新结构中作为服务组名")
    p_set.add_argument("--project", default=None, help="兼容旧命令；新结构中作为归属组名")
    p_set.add_argument("--group", default=None)
    p_set.add_argument("--service", default=None)
    p_set.set_defaults(func=cmd_set)

    p_update = sub.add_parser("update", help="更新已存在 key 的值（需真实终端确认）")
    p_update.add_argument("key")

    p_update.set_defaults(func=cmd_update)

    p_delete = sub.add_parser("delete", help="删除某个 key（需真实终端确认）")
    p_delete.add_argument("key")
    p_delete.set_defaults(func=cmd_delete)

    args = ap.parse_args()
    global VAULT_DIR, VAULT_FILE
    VAULT_DIR = str(args.vault_home)
    VAULT_FILE = str(args.vault_home / "vault.json")
    if getattr(args, "key", None) in {"VAULT_SYNC_DEVICE_TOKEN", "VAULT_SYNC_ENCRYPTION_KEY"}:
        die("此名称保留给同步工具。")
    if args.cmd == "set":
        if args.stdin:
            if sys.stdin.isatty():
                die("--stdin 需要通过管道或重定向输入。")
            args.value = sys.stdin.read().removesuffix("\n")
        elif sys.stdin.isatty():
            args.value = getpass.getpass("凭据值（不显示）：")
        else:
            die("请在终端输入凭据值，或使用 --stdin。")
    elif args.cmd == "update":
        if not sys.stdin.isatty():
            die("update 需要交互终端。")
        args.value = getpass.getpass("新值（不显示）：")
    with vault_lock(args.vault_home):
        if args.cmd == "init" and args.force and (args.vault_home / "cloud-sync.json").exists():
            die("当前库已配置同步，拒绝清空。")
        args.func(args)


if __name__ == "__main__":
    main()
