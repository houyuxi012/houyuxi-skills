# Houyuxi Skills

侯钰熙自研自用的 AI Skills 集合，沉淀可复用的工程自动化、开发效率与工作流能力。

## Skills 目录

| Skill | 说明 | 适配平台 | 状态 |
| --- | --- | --- | --- |
| [`avoiding-macos-junk-files`](skills/avoiding-macos-junk-files/SKILL.md) | 防止 `.DS_Store`、`._*`、AppleDouble、资源叉和扩展属性进入 Git、CI、SCP 与 ZIP/TAR 交付物；提供扫描、清理、暂存、SCP、归档验证和仓库门禁能力。 | Codex、Claude Code | 已发布（[v1.1.0](https://github.com/houyuxi012/houyuxi-skills/releases/tag/v1.1.0)） |

## npx 安装

安装器包 [`@houyuxi/skills@1.1.0`](https://www.npmjs.com/package/@houyuxi/skills) 已发布，可使用以下命令自动安装首个 Skill：

```bash
npx @houyuxi/skills add avoiding-macos-junk-files --target both
```

支持 `--target codex|claude|both`、`--version`、`--force` 和 `--dry-run`。安装器通过 HTTPS 下载 GitHub Release，并在写入前校验 SHA-256。

## 许可证

本仓库采用 [Apache License 2.0](LICENSE)：允许使用、修改和再分发，同时保留署名、免责与专利授权条款。完整授权文本以仓库根目录的 `LICENSE` 文件为准。

## 作者与联系

版权所有 © 侯钰熙。邮箱：[houyuxi123@gmail.com](mailto:houyuxi123@gmail.com)；网站：[www.houyuxi.com](https://www.houyuxi.com)。
