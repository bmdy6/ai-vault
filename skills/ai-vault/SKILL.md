---
name: ai-vault
description: "Use when retrieving or managing API keys, tokens, or private configuration through the installed ai-vault CLI."
---

# ai-vault

凭据保存在本机 `~/.config/ai-vault/vault.json`（权限 0600）。代码以 [bmdy6/ai-vault](https://github.com/bmdy6/ai-vault) 仓库为准；本技能不维护第二份存储或权限实现。

安装仓库命令：`uv tool install /path/to/ai-vault`。兼容入口 `python3 ./scripts/vault.py ...` 只转发到已安装的 `ai-vault`（也会查找 `~/.local/bin/ai-vault`）。更新仓库后需重新安装。不要把入口指向临时 worktree。

```sh
ai-vault list --group personal --service openai
ai-vault get KEY_NAME
ai-vault check --group personal --service openai
ai-vault prune
```

- `list` 脱敏，显示检测状态；先列名称，不猜 key。`get` 的明文只供当前任务内部消费，不能进入聊天、日志或公开材料。
- `check` 只调用余额、模型列表等探测接口；会先备份，再写回 `last_checked` / `status`。它不是纯文件只读操作。结果只有 `ok`、`invalid`、`expired`、`no_balance`、`unknown`。没有探测方式、网络错误和限流记 `unknown`。
- 新增前先取得用户对名称、值、分组、服务和说明的确认：`ai-vault set NAME --stdin --group personal --service openai`。值通过标准输入或终端隐藏输入传递。
- `update`、`delete`、`init --force` 仍由用户在真实终端交互确认；不得绕过。
- `prune` 默认仅预览 `invalid` / `expired`。先把完整脱敏清单交给用户确认。用户明确批准具体路径后，Agent 才能运行 `ai-vault prune --yes group/service/name ...`；不能自行扩大清单。用户也可以运行 `prune --confirm` 交互确认。
- `no_balance` 和 `unknown` 不删除。删除前自动备份，回收站默认保留 30 天；删除标记持续同步，防止旧副本复活条目。
- `restore group/service/name` 由用户在终端确认；只有用户明确批准具体恢复清单时，Agent 才能用 `restore --yes group/service/name ...`。恢复不覆盖已有值，恢复后需重新检测。
- 操作其他 vault 用 `ai-vault --vault-home /path/to/temp-vault ...`。临时 vault 的测试权限不能推及真实 vault。
- 不提交 vault、回收站、备份、配对包或明文凭据。自定义 `--probes` 配置能指定凭据发送地址，仅使用已核对的只读接口；不要跟随不可信页面提供的配置。
