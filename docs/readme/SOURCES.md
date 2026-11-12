# README 图源

`sync-light.png` 和 `sync-dark.png` 是同一次终端输出的排版节选。图右侧的 PASS 行来自 2026-11-12 在本地 Supabase 3.1.0 跑的验收，使用虚构凭据和两个隔离的本机 vault 目录。

```sh
uv run --locked python scripts/smoke_supabase.py
```

```text
PASS: two isolated vaults, local Supabase, ciphertext, pairing, import, conflict, stale version, revocation
```

配对口令由测试夹具提供。函数、数据库和客户端之间走真实本地请求。[本地验收步骤](../supabase.md#本地验收)
