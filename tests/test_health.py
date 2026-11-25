import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import ai_vault as vault
import vault_health as health


class HealthTests(unittest.TestCase):
    def test_five_states_and_uncertain_responses(self):
        probe = {'rules': [
            {'status': 'expired', 'http': [401], 'contains': ['expired']},
            {'status': 'invalid', 'http': [401]},
            {'status': 'no_balance', 'http': [402]},
            {'status': 'ok', 'http': [200], 'field': 'data', 'exists': True}]}
        for code, body, expected in [(200, '{"data":[]}', 'ok'), (401, '{}', 'invalid'),
                                     (401, '{"error":"expired"}', 'expired'), (402, '{}', 'no_balance'),
                                     (429, '{}', 'unknown'), (403, 'Cloudflare', 'unknown'),
                                     (200, '<html>blocked</html>', 'unknown')]:
            self.assertEqual(health.classify(probe, code, body)[0], expected)

    def test_prune_preview_explicit_selection_and_restore(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(vault, 'VAULT_DIR', tmp), patch.object(vault, 'VAULT_FILE', str(Path(tmp)/'vault.json')):
            data = {'g': {'s': {s: {'value': 'fixture-value-'+s, 'status': s} for s in ['invalid','expired','no_balance','unknown','ok']}}}
            vault.save_vault(data)
            before = Path(vault.VAULT_FILE).read_bytes()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                health.prune(vault, [], False, False)
            self.assertEqual(Path(vault.VAULT_FILE).read_bytes(), before)
            self.assertNotIn('fixture-value', out.getvalue())
            with self.assertRaises(SystemExit):
                health.prune(vault, [], True, False)
            with contextlib.redirect_stdout(io.StringIO()):
                health.prune(vault, ['g/s/invalid','g/s/expired'], True, False)
            self.assertEqual(set(vault.load_vault()['g']['s']), {'no_balance','unknown','ok'})
            self.assertTrue(list(Path(tmp).glob('backups/*.json')))
            with contextlib.redirect_stdout(io.StringIO()):
                health.restore(vault, ['g/s/invalid'], True)
            self.assertEqual(vault.load_vault()['g']['s']['invalid']['value'], 'fixture-value-invalid')

    def test_tombstone_dominates_stale_copy_but_explicit_restore_wins(self):
        import vault_sync as sync
        live = {'K': {'group':'g','service':'s','entry':{'value':'fixture'}}}
        deleted = {'K': {'group':'g','service':'s','entry':{'_deleted_at':'2026-11-25T00:00:00+00:00'}}}
        merged, incoming, outgoing = sync.merge_records(live, deleted)
        self.assertIn('_deleted_at', merged['K']['entry'])
        restored = {'K': {'group':'g','service':'s','entry':{'value':'fixture','status':'unknown','_restored_at':'2026-11-25T00:00:01+00:00'}}}
        self.assertEqual(sync.merge_records(restored, deleted)[0], restored)

    def test_fake_http_check_writes_five_states_filters_and_throttles(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        import time
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                calls.append((time.monotonic(), self.headers.get('User-Agent')))
                state = self.path.strip('/')
                code, body = {'ok':(200,'{"data":[]}'), 'invalid':(401,'{}'),
                              'expired':(401,'{"error":"expired"}'), 'no_balance':(402,'{}'),
                              'unknown':(429,'{}')}[state]
                self.send_response(code)
                self.end_headers()
                self.wfile.write(body.encode())
        server = ThreadingHTTPServer(('127.0.0.1',0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp, patch.object(vault,'VAULT_DIR',tmp), patch.object(vault,'VAULT_FILE',str(Path(tmp)/'vault.json')):
                states=['ok','invalid','expired','no_balance','unknown']
                data={'g':{'fake':{state:{'value':state} for state in states}},'other':{'fake':{'skip':{'value':'skip'}}}}
                vault.save_vault(data)
                probes=[{'id':'fake','services':['fake'],'keys':['*'],'url':f'http://127.0.0.1:{server.server_port}/{{key}}',
                         'rules':[{'status':'expired','http':[401],'contains':['expired']},
                                  {'status':'invalid','http':[401]},{'status':'no_balance','http':[402]},
                                  {'status':'ok','http':[200],'field':'data'}]}]
                p=Path(tmp)/'probes.json';p.write_text(json.dumps(probes))
                with contextlib.redirect_stdout(io.StringIO()):
                    rows=health.check(vault,'g','fake',p)
                self.assertEqual([r['status'] for r in rows], states)
                self.assertEqual({r['status'] for r in health.candidates(vault,vault.load_vault())},{'invalid','expired'})
                self.assertNotIn('status',vault.load_vault()['other']['fake']['skip'])
                self.assertTrue(all(b[0]-a[0]>=1 for a,b in zip(calls,calls[1:])))
                self.assertTrue(all('Mozilla' in c[1] for c in calls))
                self.assertTrue(list(Path(tmp).glob('backups/*.json')))
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_full_two_device_deletion_stale_copy_and_restore(self):
        import copy
        import vault_sync as sync
        class Cloud:
            state = None
            version = 0
            def __init__(self, *args):
                pass
            def read(self,key,blocked):
                if self.state is None:
                    return 0, {}
                return self.version, sync.validate_records(sync.unseal(self.state,key),blocked,['g'])
            def append(self,records,key,version):
                self.assert_version(version)
                Cloud.state=sync.seal({'format':3,'scope':['g'],'records':records},key)
                Cloud.version+=1
                return self.version
            def assert_version(self, version):
                if version!=self.version:raise sync.SyncError('version conflict')
        with tempfile.TemporaryDirectory() as tmp, patch.object(sync,'Cloud',Cloud):
            homes=[Path(tmp)/n for n in ('a','b','stale')]
            for home in homes:
                home.mkdir()
                v=sync.load_vault_module(home)
                v.save_vault({'g':{'s':{'K':{'value':'sensitive-fixture','status':'invalid'}}},
                              'personal-infra':{'vault-sync':{sync.TOKEN_KEY:{'value':'fixture-device'},sync.MASTER_KEY:{'value':sync.encode(bytes(range(32)))}}}})
                (home/'cloud-sync.json').write_text(json.dumps({'endpoint':'http://127.0.0.1:1234/functions/v1/vault-sync','allowed_groups':['g']}))
            a,b,stale=homes
            self.assertTrue(sync.sync(a,True)['verified'])
            with contextlib.redirect_stdout(io.StringIO()):
                health.prune(sync.load_vault_module(a),['g/s/K'],True)
            self.assertTrue(sync.sync(a,True)['verified'])
            before=(b/'vault.json').read_bytes()
            self.assertEqual(sync.sync(b)['delete_local'],1)
            self.assertEqual((b/'vault.json').read_bytes(),before)
            for home in (b,stale,a,b):
                self.assertTrue(sync.sync(home,True)['verified'])
                self.assertIsNone(sync.load_vault_module(home).find_entry(sync.load_vault_module(home).load_vault(),'K'))
            with contextlib.redirect_stdout(io.StringIO()):
                health.restore(sync.load_vault_module(a),['g/s/K'],True)
            for home in (a,b,stale):
                self.assertTrue(sync.sync(home,True)['verified'])
                self.assertIsNotNone(sync.load_vault_module(home).find_entry(sync.load_vault_module(home).load_vault(),'K'))
            self.assertNotIn('sensitive-fixture',json.dumps(Cloud.state))

    def test_interactive_prune_cancel_and_restore_overwrite_protection(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(vault,'VAULT_DIR',tmp), patch.object(vault,'VAULT_FILE',str(Path(tmp)/'vault.json')):
            vault.save_vault({'g':{'s':{'K':{'value':'fixture','status':'invalid'}}}})
            with contextlib.redirect_stdout(io.StringIO()), patch('sys.stdin.isatty',return_value=True), patch('builtins.input',return_value='CONFIRM'):
                health.prune(vault,['g/s/K'],False,True)
            data=vault.load_vault();data['g']={'s':{'K':{'value':'replacement'}}};vault.save_vault(data)
            before=Path(vault.VAULT_FILE).read_bytes()
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                health.restore(vault,['g/s/K'],True)
            self.assertEqual(Path(vault.VAULT_FILE).read_bytes(),before)

    def test_no_redirect_and_network_error_does_not_leak_secret(self):
        import subprocess
        probe={'url':'https://example.test/{key}','headers':{'Authorization':'Bearer {key}'}}
        with patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,'redirect\n302','')) as run:
            code,body=health.request(probe,'private-fixture-secret')
            self.assertEqual(code,302)
            self.assertNotIn('private-fixture-secret',str(run.call_args.args[0]))
            self.assertNotIn('--location',run.call_args.args[0])
        with patch('subprocess.run',return_value=subprocess.CompletedProcess([],60,'','private-fixture-secret')):
            with self.assertRaisesRegex(OSError,'Probe connection failed'):
                health.request(probe,'private-fixture-secret')

    def test_expired_trash_purged_but_deletion_marker_is_permanent(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(vault,'VAULT_DIR',tmp), patch.object(vault,'VAULT_FILE',str(Path(tmp)/'vault.json')):
            data={'g':{'s':{'old':{'value':'old','status':'invalid'},'new':{'value':'new','status':'expired'}}}}
            health.delete_paths(data,[['g','s','old']],-1)
            self.assertFalse(data[health.META]['trash'])
            self.assertTrue(data[health.META]['tombstones'])
            vault.save_vault(data)
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                health.restore(vault,['g/s/old'],True)
            with contextlib.redirect_stdout(io.StringIO()):
                health.prune(vault,['g/s/new'],True)
            self.assertEqual(len(vault.load_vault()[health.META]['tombstones']),2)

    def test_relay_credentials_are_not_sent_to_official_provider(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(vault,'VAULT_DIR',tmp), patch.object(vault,'VAULT_FILE',str(Path(tmp)/'vault.json')):
            vault.save_vault({'g':{'openai':{'OPENAI_API_KEY':{'value':'sk-fixture-private'},'OPENAI_BASE_URL':{'value':'https://relay.example.test/v1'}}}})
            with patch.object(health,'request') as request, contextlib.redirect_stdout(io.StringIO()):
                rows=health.check(vault)
            request.assert_not_called()
            self.assertTrue(all(r['status']=='unknown' for r in rows))

    def test_stale_live_check_cannot_erase_restore_marker(self):
        import vault_sync as sync
        restored={'K':{'group':'g','service':'s','entry':{'value':'fixture','status':'unknown','_restored_at':'2026-11-25T00:00:02+00:00'}}}
        stale={'K':{'group':'g','service':'s','entry':{'value':'fixture','status':'invalid','last_checked':'2026-11-25T00:00:01+00:00'}}}
        merged=sync.merge_records(restored,stale)[0]
        self.assertEqual(merged['K']['entry']['_restored_at'],'2026-11-25T00:00:02+00:00')
        self.assertEqual(merged['K']['entry']['status'],'unknown')
        deletion={'K':{'group':'g','service':'s','entry':{'_deleted_at':'2026-11-25T00:00:00+00:00'}}}
        self.assertIn('value',sync.merge_records(merged,deletion)[0]['K']['entry'])

    def test_all_builtin_probe_success_and_auth_failure_rules(self):
        from importlib.resources import files
        probes=json.loads(files('ai_vault_data').joinpath('probes.json').read_text())
        success={'openai':'{"data":[]}', 'deepseek':'{"is_available":true,"balance_infos":[]}',
                 'anthropic':'{"data":[]}', 'commandcode':'{"credits":{}}', 'pixabay':'{"hits":[]}',
                 'github':'{"login":"fixture"}', 'telegram':'{"ok":true}',
                 'linear':'{"data":{"viewer":{"id":"fixture"}}}', 'supabase':'[]'}
        self.assertEqual(set(success),{p['id'] for p in probes})
        for probe in probes:
            self.assertEqual(health.classify(probe,200,success[probe['id']])[0],'ok')
            self.assertEqual(health.classify(probe,401,'{"error":"unauthorized"}')[0],'invalid')
            self.assertEqual(health.classify(probe,429,'{}')[0],'unknown')
        deepseek=next(p for p in probes if p['id']=='deepseek')
        self.assertEqual(health.classify(deepseek,200,'{"is_available":false,"balance_infos":[]}')[0],'no_balance')

    def test_cancel_and_nonterminal_confirmation_preserve_vault(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(vault,'VAULT_DIR',tmp), patch.object(vault,'VAULT_FILE',str(Path(tmp)/'vault.json')):
            vault.save_vault({'g':{'s':{'K':{'value':'fixture-private-key','status':'invalid'}}}})
            before=Path(vault.VAULT_FILE).read_bytes()
            for terminal,answer in [(False,''),(True,'CANCEL')]:
                with patch('sys.stdin.isatty',return_value=terminal), patch('builtins.input',return_value=answer), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    health.prune(vault,['g/s/K'],False,True)
                self.assertEqual(Path(vault.VAULT_FILE).read_bytes(),before)
            self.assertFalse((Path(tmp)/'backups').exists())

    def test_cloud_append_format3_and_rejects_unsafe_markers(self):
        import vault_sync as sync
        records={'K':{'group':'g','service':'s','entry':{'_deleted_at':'2026-11-25T00:00:00+00:00'}}}
        cloud=sync.Cloud('http://127.0.0.1:1234/functions/v1/vault-sync','fixture-token',['g'])
        key=bytes(range(32))
        with patch.object(cloud,'call',return_value={'version':2}) as call:
            self.assertEqual(cloud.append(records,key,1),2)
            plain=sync.unseal(call.call_args.args[0]['payload'],key)
        self.assertEqual(plain['format'],3)
        self.assertEqual(sync.validate_records(plain,set(),['g']),records)
        import copy
        for entry in [{'_deleted_at':'not-a-time'}, {'_deleted_at':'2026-11-25T00:00:00+00:00','value':'private-fixture'}, {'_deleted_at':'2026-11-25T00:00:00'}]:
            bad=copy.deepcopy(plain);bad['records']['K']['entry']=entry
            with self.assertRaises(sync.SyncError):
                sync.validate_records(bad,set(),['g'])

    def test_lifecycle_scope_and_bootstrap_exclusions(self):
        import vault_sync as sync
        data={'g':{'s':{'K':{'value':'fixture'}}},'other':{'s':{'K':{'value':'private'}}}}
        health.delete_paths(data,[['g','s','K'],['other','s','K']])
        self.assertEqual(set(sync.records_from(data,set(),['g'])),{'K'})
        self.assertEqual(sync.records_from(data,{'K'},['g']),{})
        data[health.META]['tombstones']['bootstrap']={'path':['g','s',sync.TOKEN_KEY],'deleted_at':health.now()}
        self.assertNotIn(sync.TOKEN_KEY,sync.records_from(data,set(),['g']))
