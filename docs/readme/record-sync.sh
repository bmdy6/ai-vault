#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

db='postgresql://postgres:postgres@127.0.0.1:54322/postgres'
endpoint='http://127.0.0.1:54321/functions/v1/vault-sync'
sql() {
  psql -XqAt -v ON_ERROR_STOP=1 "$db" "$@"
}
if [[ "$(sql -c 'select (select count(*) from public.vault_sync_devices) + (select count(*) from public.vault_sync_snapshots)')" != 0 ]]; then
  printf '%s\n' 'Use a fresh disposable local Supabase project.' >&2
  exit 1
fi

scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
first="$scratch/first"
second="$scratch/second"
bundle="$scratch/second.pairing"
ai-vault() { command ai-vault --vault-home "$first" "$@"; }
ai-vault init >/dev/null
source docs/readme/capture-inputs/two-vaults/first-device.sh >/dev/null
unset -f ai-vault

ai-vault-sync --vault-home "$first" init-sync \
  --endpoint "$endpoint" --group personal | sql >/dev/null
uploaded=$(ai-vault-sync --vault-home "$first" sync --apply)
python3 -c 'import json, sys; assert json.load(sys.stdin)["verified"]' <<< "$uploaded"

# As in the smoke test, substitute only the interactive pairing input.
python3 - "$first" "$second" "$bundle" >/dev/null <<'PY'
from pathlib import Path
import sys
from unittest.mock import patch

import vault_sync

first, second, bundle = map(Path, sys.argv[1:])
with patch.object(vault_sync, "require_terminal"), patch.object(
    vault_sync.getpass, "getpass", return_value="readme-demo-only"
):
    vault_sync.pair(first, bundle)
    vault_sync.join(second, bundle)
PY

if ai-vault --vault-home "$second" get DEMO_API_KEY >/dev/null 2>&1; then
  printf '%s\n' 'Device 2 already had the sample before sync.' >&2
  exit 1
fi
imported=$(ai-vault-sync --vault-home "$second" sync --apply)
added=$(python3 -c 'import json, sys; r = json.load(sys.stdin); assert r["verified"] and r["added_local"] == 1; print(r["added_local"])' <<< "$imported")
value=$(ai-vault --vault-home "$second" get DEMO_API_KEY)
[[ "$value" == demo-value ]]
[[ "$(sql -c "select count(*) from public.vault_sync_snapshots where payload::text like '%demo-value%'")" == 0 ]]
printf '%s\n' '$ ai-vault-sync sync \' '  --apply' "added_local: $added" \
  '$ ai-vault get \' '  DEMO_API_KEY' "$value"
