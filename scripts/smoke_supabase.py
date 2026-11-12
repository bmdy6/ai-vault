"""Exercise the shipped client, Edge Function and SQL against a fresh local stack."""
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from unittest.mock import patch

import vault_sync as sync

ENDPOINT = "http://127.0.0.1:54321/functions/v1/vault-sync"
DATABASE = "postgresql://postgres:postgres@127.0.0.1:54322/postgres"
FIXTURE = "synthetic-value-for-local-test"
KEY = "DEMO_API_KEY"


def sql(statement):
    return subprocess.run(
        ["psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", DATABASE],
        input=statement, text=True, capture_output=True, check=True, timeout=20,
    ).stdout.strip()


def cli(module, home, *args, stdin=None, ok=True):
    result = subprocess.run(
        [sys.executable, "-m", module, "--vault-home", str(home), *args],
        input=stdin or "", text=True, capture_output=True, timeout=60,
    )
    if (result.returncode == 0) != ok:
        raise RuntimeError(f"Unexpected exit for {module} {args[0]}: {result.stderr}")
    return result


def main():
    if sql("select count(*) from public.vault_sync_devices") != "0":
        raise SystemExit("Use a fresh disposable local Supabase project.")
    if sql("select count(*) from public.vault_sync_snapshots") != "0":
        raise SystemExit("Local snapshots already exist.")
    for role in ("anon", "authenticated"):
        allowed = sql(
            f"select has_table_privilege('{role}', 'public.vault_sync_snapshots', 'SELECT')"
            f" or has_table_privilege('{role}', 'public.vault_sync_devices', 'INSERT');"
        )
        assert allowed == "f", f"Unexpected direct access for {role}"

    with tempfile.TemporaryDirectory(prefix="ai-vault-demo-") as tmp:
        root = Path(tmp)
        first, second = root / "first", root / "second"
        cli("ai_vault", first, "init")
        cli("ai_vault", first, "set", KEY, "--group", "personal", "--service", "demo",
            "--stdin", stdin=FIXTURE)
        assert FIXTURE not in cli("ai_vault", first, "list").stdout
        sql(cli("vault_sync", first, "init-sync", "--endpoint", ENDPOINT, "--group", "personal").stdout)
        cli("vault_sync", first, "init-sync", "--endpoint", ENDPOINT, "--group", "personal", ok=False)
        preview = json.loads(cli("vault_sync", first, "sync").stdout)
        assert (preview["version"], preview["add_cloud"]) == (0, 1)
        assert sql("select count(*) from public.vault_sync_snapshots") == "0"
        uploaded = json.loads(cli("vault_sync", first, "sync", "--apply").stdout)
        assert uploaded["verified"] and uploaded["version"] > 0

        assert sql(f"select count(*) from public.vault_sync_snapshots where payload::text like '%{FIXTURE}%';") == "0"
        bundle = root / "second.pairing"
        # Only terminal input is substituted. Pairing uses the real local backend.
        with patch.object(sync, "require_terminal"), patch.object(
            sync.getpass, "getpass", return_value="synthetic-pairing-passphrase"
        ):
            sync.pair(first, bundle)
            sync.join(second, bundle)
        assert stat.S_IMODE(bundle.stat().st_mode) == 0o600
        assert stat.S_IMODE((second / "vault.json").stat().st_mode) == 0o600
        preview = json.loads(cli("vault_sync", second, "sync").stdout)
        assert preview["add_local"] == 1
        imported = json.loads(cli("vault_sync", second, "sync", "--apply").stdout)
        assert imported["verified"] and imported["added_local"] == 1
        assert cli("ai_vault", second, "get", KEY).stdout.strip() == FIXTURE

        vault = sync.load_vault_module(second)
        store = vault.load_vault()
        store["personal"]["demo"][KEY]["value"] = "synthetic-conflict"
        vault.save_vault(store)
        before = sql("select max(version) from public.vault_sync_snapshots")
        failure = cli("vault_sync", second, "sync", "--apply", ok=False)
        assert "冲突" in failure.stderr
        assert cli("ai_vault", second, "get", KEY).stdout.strip() == "synthetic-conflict"
        assert sql("select max(version) from public.vault_sync_snapshots") == before

        master = sync.decode(sync.entry_value(vault, sync.MASTER_KEY))
        token = sync.entry_value(vault, sync.TOKEN_KEY)
        cloud = sync.Cloud(ENDPOINT, token, ["personal"])
        _, records = cloud.read(master, set())
        try:
            cloud.append(records, master, expected_version=0)
        except sync.SyncError as exc:
            assert "版本" in str(exc)
        else:
            raise AssertionError("The server accepted an outdated snapshot version.")
        assert sql("select max(version) from public.vault_sync_snapshots") == before
        sql(f"update public.vault_sync_devices set revoked=true where device_id='{sync.config_for(second)['device_id']}'")
        rejected = cli("vault_sync", second, "sync", ok=False)
        assert "未授权" in rejected.stderr
        assert json.loads(cli("vault_sync", first, "sync").stdout)["version"] == int(before)

    print("PASS: two isolated vaults, local Supabase, ciphertext, pairing, import, conflict, stale version, revocation")


if __name__ == "__main__":
    main()
