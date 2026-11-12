# ai-vault

在本机按分组管理 AI 工具和脚本用的 API Key。需要换电脑时，可以选择分组，在本机加密后同步到自己的 Supabase，再用加密配对包接入第二台设备。

Local credentials for personal AI tools, with optional encrypted snapshot sync to your own Supabase project.

## 本机用法

需要 macOS 或 Linux、Python 3.10+。只有云同步需要 `curl` 和 Supabase。

```sh
git clone https://github.com/bmdy6/ai-vault.git
cd ai-vault
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
ai-vault init
ai-vault set EXAMPLE_API_KEY --group personal --service demo
ai-vault list --group personal
```

`set` 在终端隐藏输入。自动化可以从受信任的程序经管道使用 `set --stdin`。列表隐藏值。只有明确执行 `get` 才会把值写到标准输出，可以把输出交给需要它的本地进程。更新和删除需要在终端输入名称确认。

```sh
ai-vault update EXAMPLE_API_KEY
ai-vault delete EXAMPLE_API_KEY
```

默认数据目录是 `~/.config/ai-vault`。如果这台电脑已有 ai-vault，先用 `--vault-home` 试用独立目录。两个命令都在子命令前接受这个选项。

## 多设备同步

部署一次 [Supabase 函数和数据库迁移](docs/supabase.md)，再用自己的项目地址登记第一台设备。这里的域名是示例。

```sh
ai-vault-sync init-sync \
  --endpoint https://YOUR_PROJECT_REF.supabase.co/functions/v1/vault-sync \
  --group personal
```

在 Supabase SQL Editor 执行终端显示的设备登记 SQL。SQL 只包含设备 ID 和令牌摘要。加密主密钥和设备令牌在本机生成。

```sh
ai-vault-sync sync          # 预览新增数量
ai-vault-sync sync --apply  # 同步新增项并回读核对
ai-vault-sync pair second-device.pairing
```

把配对文件传给自己的第二台电脑，口令单独传递。接入后先预览。

```sh
ai-vault-sync join second-device.pairing
ai-vault-sync sync
ai-vault-sync sync --apply
```

同名记录不一致时同步停止。核对后可在终端运行 `ai-vault-sync resolve EXAMPLE_API_KEY --use local` 或 `--use cloud`，再同步。删除本机值不会传播删除，云端仍有该值时，同步可将其重新导入。云端快照会保留历史。

## 数据与权限

- **本机是明文 JSON。** 应用新建的文件权限是 `0600`。请保护你的系统账户、备份以及 `get` 的输出。
- **云端保存加密快照。** 客户端用 AES-256-GCM 加密后发送。设备 ID、快照版本、条数和时间等元数据仍可见。
- **每个实例供一位用户的可信设备共用。** 分组选择控制本机同步范围。配对设备共享主密钥，已授权设备可以读取同一云端快照和登记新设备。
- 配对包有口令保护，并含加入所需的主密钥和设备令牌。用完后删除传输副本。保管好独立的恢复副本。只剩 Supabase 密文时，无法恢复遗失的主密钥。
- 如需撤销设备访问，在自己的实例中按设备 ID 撤销令牌。撤销只会停止该设备后续访问。对已泄露的业务凭据或主密钥，需要另行更换。

## 开发与验证

```sh
python -m unittest discover -s tests -v
```

本地 Supabase 的完整验证步骤见[部署与验证](docs/supabase.md)。公开仓库中的示例和测试使用虚构凭据。

[MIT](LICENSE)
