---
name: avoiding-macos-junk-files
description: Use when macOS 文件、目录、Git 仓库、CI 流水线、SCP 传输或 ZIP/TAR 制品可能包含 ._*, .DS_Store, __MACOSX, AppleDouble, 资源叉或扩展属性等平台元数据污染。
---

# 避免 macOS 垃圾文件

使用随附 CLI 管理 macOS 元数据进入复制、Git、CI、SCP 和归档交付链路的风险。该技能阻止元数据进入交付物，不能保证 Finder 永不在本机磁盘产生元数据。

## 核心原则

- 默认只检查；仅在用户明确授权并传入 `--apply` 时执行清理或安装仓库门禁。
- 把 `.DS_Store`、`._*`、`__MACOSX`、AppleDouble、资源叉和扩展属性视为交付污染；将不确定项转为人工复核，不擅自删除。需要读取 FinderInfo、ResourceFork 与 `com.apple.metadata:*` 时显式使用 `scan <目录> --xattrs`。
- 使用 CLI 的退出码：`0` 通过、`1` 发现策略违规、`2` 运行错误。
- 不修改 macOS 全局设置、用户 Shell 配置或 Git 全局配置。

## 默认安全流程

1. 先扫描：`python3 scripts/macos_hygiene.py scan <目录>`。需要机器可读结果时附加 `--format json`；需要检查传输相关扩展属性时附加 `--xattrs`。用 `--version` 记录工具版本。
2. 仅在授权后清理高置信垃圾：先运行 `clean <目录>` 预览，再运行 `clean <目录> --apply`；人工复核项保持不动。
3. 对 Git 仓库运行 `check-git <仓库> --scope all`，覆盖工作区、暂存区和已跟踪路径。
4. 为仓库预览门禁：`install-repo-guard <仓库> --ci both`；确认无冲突后使用 `--apply` 安装本地 Hook、仓库内工具和 CI 模板。Hook 可被 `--no-verify` 绕过，因此必须保留 CI 门禁。
5. 使用 `stage <源目录> <暂存目录> --manifest <清单路径>` 构造无污染传输副本并生成 SHA-256 清单；使用 `scp <源目录> <目标> --manifest-out <清单路径>` 时让工具完成暂存、复检、传输并保留可复核审计清单。仅使用受限的 SCP 选项，拒绝可执行本地命令的配置。
6. 使用 `archive create <源目录> <制品> --format zip|tar|tar.gz` 创建归档；交付前运行 `archive verify <制品>`，验证完整性、危险路径/链接、资源限制和元数据污染。容量受限的 CI 必须按环境收紧 `--max-members`、`--max-total-bytes`、`--max-member-bytes` 和 `--max-compression-ratio`。

## 禁止事项

- 不直接用 Finder 的“压缩”结果作为发布制品，除非已经通过 `archive verify`。
- 不以 `.gitignore` 替代 Git 索引、已跟踪文件、Hook 或 CI 检查。
- 不将未复核的资源叉、扩展属性或异常符号链接纳入 SCP 暂存区和归档。
- 不用 `--no-verify` 作为放行手段；仅可用于证明 CI 仍会阻断。

## 验收标准

在发布、传输或合并前，确认扫描、`check-git`、SCP 暂存清单和归档验证均返回 `0`；CI 使用同一检查命令且失败时阻断流水线。随附 GitHub Actions 与 GitLab CI 模板在 Python 3.11、3.14 矩阵中执行该检查；安装后应在目标托管平台实际运行一次，并保留流水线链接或日志作为环境验收证据。归档验收检查 ZIP/TAR **内部**成员路径、ZIP extra/resource-fork 记录和 TAR 内部 xattr；宿主文件本体的文件系统 xattr 不属于归档内容，也不会随此归档格式写入成员。若返回 `1`，先处理或隔离发现项；若返回 `2`，修复运行环境或输入错误后重试。

## 安全边界

- 暂存和归档会创建私有临时副本；为其预留不低于有效源内容大小的本地空间，并在 CI 上用归档资源上限限制可处理的规模。
- 本工具在单次、单线程传输上下文中固定文件描述符并复检；它不能防御拥有同一 UID 且可任意修改源目录、临时目录或运行环境的恶意本地进程。
- `--xattrs` 只检测会进入交付载荷的 FinderInfo、ResourceFork 与 `com.apple.metadata:*`。`com.apple.provenance` 等宿主层属性不等同于压缩包成员污染，须由存储或传输端另行治理。

## 版权与联系信息

版权所有 © 侯钰熙。联系邮箱：[houyuxi123@gmail.com](mailto:houyuxi123@gmail.com)；网站：[www.houyuxi.com](https://www.houyuxi.com)。
