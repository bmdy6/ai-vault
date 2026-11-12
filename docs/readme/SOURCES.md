# README 图源

首屏展示两套临时 vault 与本地 Supabase 3.1.0 的实际交互。第一套写入虚构的 `DEMO_API_KEY`，上传加密快照并回读核对。第二套先配对，确认本地尚无该 Key，再同步并读取。图里的 `added_local` 取自第二台的同步结果，`demo-value` 是随后读取到的示例值。

图中为便于阅读省略了临时 `--vault-home`。配对使用测试口令自动完成输入，凭据同步请求经过真实的 Edge Function 和数据库。 [输入脚本](capture-inputs/two-vaults/first-device.sh) · [运行记录](captures/two-vaults.json) · [图像清单](art-manifest.json)

按[本地验收步骤](../supabase.md#本地验收)启动一套空白的本地实例，安装 `psql`，然后从仓库根目录运行：

```sh
uv run --quiet --locked bash docs/readme/record-sync.sh
```

脚本只访问本地回环地址，检测到已有设备或快照时会退出。每次复现使用单独的空白测试实例。

使用 [readme-from-code v0.4.1](https://github.com/bmdy6/skill-readme-from-code/tree/94cd4289788378d1ec83d93447c6ab77e1be0f95) 的 `art` 命令和同目录的 `art.json` 可重渲染浅色与深色图。
