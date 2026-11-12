-- 个人凭据仅以客户端密文快照保存；设备只登记令牌摘要。
create table public.vault_sync_devices (
 device_id text primary key,
 token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
 created_at timestamptz not null default now(),
 revoked boolean not null default false
);
create table public.vault_sync_snapshots (
 version bigint generated always as identity primary key,
 payload jsonb not null,
 entry_count integer not null check (entry_count between 0 and 10000),
 ciphertext_sha256 text not null,
 device_id text not null references public.vault_sync_devices(device_id),
 created_at timestamptz not null default now()
);
alter table public.vault_sync_devices enable row level security;
alter table public.vault_sync_snapshots enable row level security;
revoke all on public.vault_sync_devices, public.vault_sync_snapshots from public, anon, authenticated;
grant select, insert on public.vault_sync_devices, public.vault_sync_snapshots to service_role;
grant usage, select on sequence public.vault_sync_snapshots_version_seq to service_role;
create policy deny_direct_device_access on public.vault_sync_devices for all to anon, authenticated using (false) with check (false);
create policy deny_direct_snapshot_access on public.vault_sync_snapshots for all to anon, authenticated using (false) with check (false);
create function public.vault_sync_append(p_expected_version bigint,p_payload jsonb,p_entry_count integer,p_ciphertext_sha256 text,p_device_id text)
returns bigint language plpgsql security invoker set search_path='' as $$
declare current_version bigint; next_version bigint;
begin
 perform pg_catalog.pg_advisory_xact_lock(742193001);
 select coalesce(max(version),0) into current_version from public.vault_sync_snapshots;
 if current_version <> p_expected_version then
  raise sqlstate 'PT409' using message='snapshot_version_conflict';
 end if;
 insert into public.vault_sync_snapshots(payload,entry_count,ciphertext_sha256,device_id)
 values(p_payload,p_entry_count,p_ciphertext_sha256,p_device_id) returning version into next_version;
 return next_version;
end; $$;
revoke all on function public.vault_sync_append(bigint,jsonb,integer,text,text) from public, anon, authenticated;
grant execute on function public.vault_sync_append(bigint,jsonb,integer,text,text) to service_role;
-- 首台设备须另外登记随机访问令牌的 SHA-256，真实令牌和加密主密钥不写入 SQL。
