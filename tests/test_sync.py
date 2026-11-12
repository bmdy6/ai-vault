"""验证加密、隔离、冲突保护和新增导入的关键行为。"""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import vault_sync as sync


class SyncTests(unittest.TestCase):
    def test_ciphertext_roundtrip_and_tamper_rejection(self):
        key = bytes(range(32))
        envelope = sync.seal({'key': 'sensitive-fixture'}, key)
        self.assertNotIn('sensitive-fixture', json.dumps(envelope))
        self.assertEqual(sync.unseal(envelope, key), {'key': 'sensitive-fixture'})
        ciphertext = bytearray(sync.decode(envelope['ciphertext']))
        ciphertext[0] ^= 1
        envelope['ciphertext'] = sync.encode(bytes(ciphertext))
        with self.assertRaises(sync.SyncError):
            sync.unseal(envelope, key)

    def test_wrong_key_and_domain_are_rejected(self):
        envelope = sync.seal({'key': 'fixture'}, bytes(range(32)))
        with self.assertRaises(sync.SyncError):
            sync.unseal(envelope, bytes(reversed(range(32))))
        with self.assertRaises(sync.SyncError):
            sync.unseal(envelope, bytes(range(32)), sync.PAIR_AAD)

    def test_unselected_group_and_bootstrap_never_enter_snapshot(self):
        data = {'personal-infra': {'svc': {'PERSONAL': {'value': 'yes'}, sync.MASTER_KEY: {'value': 'never'}, 'BLOCKED': {'value': 'never'}}}, 'another-group': {'svc': {'OTHER': {'value': 'never'}}}}
        self.assertEqual(set(sync.records_from(data, {'BLOCKED'})), {'PERSONAL'})

    def test_remote_unselected_group_and_bootstrap_are_rejected(self):
        for record in [{'group': 'another-group', 'service': 'svc', 'entry': {'value': 'x'}}, {'group': 'personal-infra', 'service': 'svc', 'entry': {'value': 'x'}}]:
            name = 'OTHER' if record['group'] == 'another-group' else sync.MASTER_KEY
            with self.assertRaises(sync.SyncError):
                sync.validate_records({'format': 1, 'scope': ['personal-infra'], 'records': {name: record}}, set())

    def test_authorized_groups_preserve_entries_and_exclude_bootstrap(self):
        """验证已选分组和启动凭据的边界。"""
        data = {'personal-infra': {'svc': {'PERSONAL': {'value': 'p'}, sync.MASTER_KEY: {'value': 'never'}, sync.TOKEN_KEY: {'value': 'never'}}}, 'another-group': {'svc': {'OTHER': {'value': 'c', 'description': '保留说明', 'extra': 42}}}}
        groups = ['personal-infra', 'another-group']
        records = sync.records_from(data, set(), groups)
        self.assertEqual(set(records), {'PERSONAL', 'OTHER'})
        self.assertEqual(records['OTHER']['entry'], data['another-group']['svc']['OTHER'])
        snapshot = {'format': 2, 'scope': groups, 'records': records}
        self.assertEqual(sync.validate_records(snapshot, set(), groups), records)
        with self.assertRaises(sync.SyncError):
            sync.validate_records(snapshot, set())

    def test_expanded_reader_accepts_legacy_personal_snapshot(self):
        """验证扩大范围后仍能读取旧个人快照。"""
        record = {'group': 'personal-infra', 'service': 'svc', 'entry': {'value': 'fixture'}}
        snapshot = {'format': 1, 'scope': ['personal-infra'], 'records': {'KEY': record}}
        self.assertEqual(sync.validate_records(snapshot, set(), ['personal-infra', 'another-group']), {'KEY': record})

    def test_same_name_in_different_services_roundtrips_without_overwrite(self):
        """验证同名服务备注完整导入原路径而不会覆盖另一项。"""
        data = {'model-providers': {'one': {'_baseurl_note': {'value': 'one'}}, 'two': {'_baseurl_note': {'value': 'two'}}}}
        groups = ['model-providers']
        records = sync.records_from(data, set(), groups)
        self.assertEqual(len(records), 2)
        self.assertEqual(len(sync.records_from(data, {'_baseurl_note'}, groups)), 0)
        snapshot = {'format': 2, 'scope': groups, 'records': records}
        self.assertEqual(sync.validate_records(snapshot, set(), groups), records)
        with tempfile.TemporaryDirectory() as d:
            vault = sync.load_vault_module(Path(d))
            vault.save_vault({})
            self.assertEqual(sync.add_records(vault, records), 2)
            self.assertEqual(vault.load_vault(), data)
            self.assertEqual(sync.add_records(vault, records), 0)
            changed = copy.deepcopy(records)
            next(iter(changed.values()))['entry']['value'] = 'changed'
            with self.assertRaises(sync.SyncError):
                sync.add_records(vault, changed)
            self.assertEqual(vault.load_vault(), data)

    def test_config_requires_explicit_nonempty_groups(self):
        """验证同步范围不能以通配符或空范围扩大。"""
        endpoint = 'https://example.supabase.co/functions/v1/vault-sync'
        for groups in [[], ['*'], ['another-group', 'another-group'], ['version'], [False]]:
            with self.assertRaises(sync.SyncError):
                sync.validate_config({'endpoint': endpoint, 'allowed_groups': groups})
        config = {'endpoint': endpoint, 'allowed_groups': ['personal-infra', 'another-group']}
        self.assertEqual(sync.validate_config(config), config)

    def test_full_sync_preserves_legacy_snapshot_and_verifies_new_cloud_version(self):
        """验证旧快照追加全业务版本并回读，不修改本机已有凭据。"""
        groups = ['personal-infra', 'another-group']
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            vault = sync.load_vault_module(home)
            data = {'personal-infra': {'svc': {'PERSONAL': {'value': 'p'}}, 'vault-sync': {sync.TOKEN_KEY: {'value': 'fixture-token'}, sync.MASTER_KEY: {'value': sync.encode(bytes(range(32)))}}}, 'another-group': {'svc': {'OTHER': {'value': 'c'}}}}
            vault.save_vault(data)
            (home/'cloud-sync.json').write_text(json.dumps({'endpoint': 'https://example.supabase.co/functions/v1/vault-sync', 'allowed_groups': groups}))
            old = sync.records_from(data, set())
            merged = sync.records_from(data, set(), groups)
            with patch.object(sync.Cloud, 'read', side_effect=[(1, old), (2, merged)]) as read, patch.object(sync.Cloud, 'append', return_value=2) as append:
                result = sync.sync(home, apply=True)
            self.assertEqual(result['add_cloud'], 1)
            self.assertTrue(result['verified'])
            self.assertEqual(result['verified_version'], 2)
            self.assertEqual(read.call_count, 2)
            self.assertEqual(append.call_args.args[0], merged)
            self.assertEqual(vault.load_vault(), data)

    def test_conflict_preserves_both_inputs(self):
        local = {'KEY': {'value': 'left'}}
        remote = {'KEY': {'value': 'right'}}
        before = copy.deepcopy((local, remote))
        with self.assertRaises(sync.SyncError):
            sync.merge_records(local, remote)
        self.assertEqual((local, remote), before)

    def test_merge_retains_remote_only_keys(self):
        merged, incoming, outgoing = sync.merge_records({'A': 1}, {'B': 2})
        self.assertEqual(merged, {'A': 1, 'B': 2})
        self.assertEqual(incoming, {'B': 2})
        self.assertEqual(outgoing, {'A': 1})

    def test_local_import_adds_and_refuses_existing_update(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            vault = sync.load_vault_module(home)
            vault.save_vault({'another-group': {'private': {'OTHER': {'value': 'preserved'}}}})
            records = {'PERSONAL': {'group': 'personal-infra', 'service': 'svc', 'entry': {'value': 'new', 'description': 'fixture'}}}
            self.assertEqual(sync.add_records(vault, records), 1)
            self.assertEqual(vault.find_entry(vault.load_vault(), 'OTHER')[2]['value'], 'preserved')
            records['PERSONAL']['entry']['value'] = 'overwrite'
            with self.assertRaises(sync.SyncError):
                sync.add_records(vault, records)
            self.assertEqual(vault.find_entry(vault.load_vault(), 'PERSONAL')[2]['value'], 'new')

    def test_overwrite_and_pairing_require_real_terminal(self):
        with patch('sys.stdin.isatty', return_value=False):
            with self.assertRaises(sync.SyncError):
                sync.require_terminal()

    def test_network_conflict_does_not_return_a_new_version(self):
        response = type('Response', (), {'returncode': 0, 'stdout': '{"error":"snapshot_version_conflict"}\n409'})()
        with patch('subprocess.run', return_value=response):
            with self.assertRaises(sync.SyncError):
                sync.Cloud('https://example.supabase.co/functions/v1/vault-sync', 'test').append({}, bytes(range(32)), 1)


if __name__ == '__main__':
    unittest.main()
