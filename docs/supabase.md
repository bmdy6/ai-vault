# Supabase 同步

每位用户用自己的 Supabase 实例。数据库保存一份个人 vault 的版本历史，Edge Function 用随机设备令牌做鉴权。

## 部署到自己的项目

以下命令使用 Supabase CLI 3.1.0。先在 Supabase 创建一个项目，打开该项目的 SQL Editor，执行 `supabase/migrations/` 中的 `vault_sync.sql` 迁移文件。首次部署需要创建表与函数。也可用 CLI 的迁移流程部署到新项目。

用你的账号登录 CLI，确认项目引用和目标一致，再部署函数。

```sh
supabase login
supabase functions deploy vault-sync --remote=YOUR_PROJECT_REF --no-verify-jwt
```

`verify_jwt = false` 让 Supabase 网关把自定义设备令牌交给函数校验。函数仅接受 POST，验证令牌摘要和撤销状态后才处理请求。项目 URL 和服务器侧 service-role 凭据由 Supabase 运行环境提供。设备端只需要项目函数地址，service-role 凭据始终留在服务器侧。

然后按 [README](../README.md#多设备同步) 初始化首台设备，并在同一 Supabase 项目的 SQL Editor 执行生成的登记语句。用 `sync` 确认能读取空快照，再加一条测试配置验证上传和回读。

有需要时，在 SQL Editor 用设备 ID 将对应 `vault_sync_devices` 记录的 `revoked` 设为 `true`。撤销后客户端会收到 HTTP 401。

- [Supabase Edge Function 配置](https://supabase.com/docs/guides/functions/function-configuration)
- [Supabase 本地迁移](https://supabase.com/docs/guides/local-development/database-migrations)

## 本地验收

在干净的本地项目里启动 Supabase。这里使用默认端口 54321 和 54322，需要 Docker。终端显示的本地测试密钥只用于该沙盒。

```sh
supabase start
supabase functions serve
```

另开终端，安装本项目后运行以下验收脚本。脚本要求空的本地数据库，只在回环地址访问。它会登记两台虚构设备，在临时目录完成初始化、加密上传、配对、导入、冲突停写和版本回读。重复运行前清空这个测试实例。

```sh
python scripts/smoke_supabase.py
```

需要迁移私有实例时先备份。更换主密钥、清理历史快照和远端删除目前由实例管理者处理。

v0.1.0 用本地 Supabase 3.1.0 和两个独立临时 vault 验证过这条流程。验收包含未授权设备、撤销设备、预览不写入、密文回读、同名冲突和旧版本拒绝。配对口令由测试夹具提供，网络与数据库走真实本地 Supabase。托管项目按本页步骤配置后需再做一次部署验收。
