# @houyuxi/skills

Houyuxi Skills 的命令行安装器。当前支持将 `avoiding-macos-junk-files` 安装到 Codex、Claude Code 或两者。

```bash
npx @houyuxi/skills add avoiding-macos-junk-files --target both
```

安装器仅下载已登记的 GitHub Release，使用 HTTPS 下载，并在解压前校验 SHA-256；校验失败时不会安装。

## 选项

```text
--target codex|claude|both  安装目标，默认 both
--version <版本>            选择受支持的发行版本，默认最新版本
--force                     原子替换已有同名 Skill
--dry-run                   仅显示目标目录，不写入文件
```

示例：

```bash
npx @houyuxi/skills add avoiding-macos-junk-files --target codex
npx @houyuxi/skills add avoiding-macos-junk-files --target claude --force
```

## 安装目录

- Codex：`~/.codex/skills/avoiding-macos-junk-files`
- Claude Code：`~/.claude/skills/avoiding-macos-junk-files`

版权所有 © 侯钰熙。邮箱：[houyuxi123@gmail.com](mailto:houyuxi123@gmail.com)；网站：[www.houyuxi.com](https://www.houyuxi.com)。
