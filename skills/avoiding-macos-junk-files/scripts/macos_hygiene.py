#!/usr/bin/env python3
"""macOS 元数据治理的统一命令行入口。"""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from typing import Any, Callable, Sequence
import zipfile

from macos_hygiene_lib.archives import (
    ArchiveCreationError,
    ArchiveLimits,
    ArchiveRuntimeError,
    create_archive,
    verify_archive,
)
from macos_hygiene_lib.cleaner import clean_tree
from macos_hygiene_lib.git_guard import check_git
from macos_hygiene_lib.installer import install_repo_guard
from macos_hygiene_lib.model import AuditReport, CleanupResult, TOOL_VERSION
from macos_hygiene_lib.reporting import render_json, render_text
from macos_hygiene_lib.scanner import scan_tree
from macos_hygiene_lib.staging import (
    ScpOptionError,
    ScpResult,
    StagingError,
    StagingPolicyError,
    TransferManifest,
    stage_tree,
    transfer_via_scp,
)

_EXIT_SUCCESS = 0
_EXIT_POLICY = 1
_EXIT_RUNTIME = 2
_TEXT_LABELS = {
    "archive": "归档",
    "command": "执行命令",
    "entries": "清单条目",
    "errors": "错误",
    "excluded": "已排除",
    "failed": "失败项",
    "manifest_path": "清单路径",
    "manual_review": "需人工复核",
    "planned": "计划",
    "removed": "已删除",
    "result": "结果",
    "returncode": "外部命令退出码",
    "skipped": "跳过",
    "source": "源目录",
    "stderr": "标准错误",
    "stdout": "标准输出",
    "target": "目标目录",
    "unchanged": "未变更",
    "written": "已写入",
}


def build_parser() -> argparse.ArgumentParser:
    """构建稳定的命令树，不在解析阶段执行任何文件系统变更。"""
    parser = argparse.ArgumentParser(description="避免 macOS 元数据污染的治理工具")
    parser.add_argument(
        "--version",
        action="version",
        version=f"macos-hygiene {TOOL_VERSION}",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="只读扫描目录")
    scan.add_argument("path", type=Path)
    scan.add_argument(
        "--xattrs",
        action="store_true",
        help="额外扫描 FinderInfo、ResourceFork 与 com.apple.metadata:* 属性",
    )
    _add_output_format(scan)

    clean = commands.add_parser("clean", help="预览或清理高置信 macOS 垃圾文件")
    clean.add_argument("path", type=Path)
    clean.add_argument("--apply", action="store_true", help="确认后执行删除")
    _add_output_format(clean)

    git_check = commands.add_parser("check-git", help="检查 Git 工作区、索引和已跟踪文件")
    git_check.add_argument("repository", type=Path)
    git_check.add_argument(
        "--scope", choices=("worktree", "index", "tracked", "all"), default="all"
    )
    _add_output_format(git_check)

    stage = commands.add_parser("stage", help="创建无 macOS 元数据的传输暂存目录")
    stage.add_argument("source", type=Path)
    stage.add_argument("target", type=Path)
    stage.add_argument("--manifest", type=Path, help="将 SHA-256 清单写到指定路径")
    _add_output_format(stage)

    scp = commands.add_parser("scp", help="暂存、复检后通过 SCP 传输")
    scp.add_argument("source", type=Path)
    scp.add_argument("destination")
    scp.add_argument("--scp-option", action="append", default=[], help="允许的 SCP 选项")
    scp.add_argument("--scp-program", default="scp", help="SCP 可执行程序路径")
    scp.add_argument(
        "--manifest-out",
        type=Path,
        help="将可复核的 SHA-256 传输清单原子写入指定路径",
    )
    _add_output_format(scp)

    archive = commands.add_parser("archive", help="创建或验证归档")
    archive_commands = archive.add_subparsers(dest="archive_command", required=True)
    archive_create = archive_commands.add_parser("create", help="创建无 macOS 元数据归档")
    archive_create.add_argument("source", type=Path)
    archive_create.add_argument("output", type=Path)
    archive_create.add_argument("--format", choices=("zip", "tar", "tar.gz"))
    archive_create.add_argument("--json", action="store_true", help="输出 JSON")
    _add_archive_limit_options(archive_create)
    archive_verify = archive_commands.add_parser("verify", help="验证归档安全性与完整性")
    archive_verify.add_argument("archive", type=Path)
    _add_archive_limit_options(archive_verify)
    _add_output_format(archive_verify)

    install = commands.add_parser("install-repo-guard", help="预览或安装 Git 与 CI 门禁")
    install.add_argument("repository", type=Path)
    install.add_argument("--ci", choices=("none", "github", "gitlab", "both"), default="both")
    install.add_argument("--apply", action="store_true", help="确认后写入仓库配置")
    install.add_argument(
        "--skill-root",
        type=Path,
        default=_default_skill_root(),
        help="技能根目录，默认根据当前脚本位置推导",
    )
    _add_output_format(install)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """执行一个命令并返回统一的 0/1/2 退出码。"""
    parser = build_parser()
    arguments = parser.parse_args(argv)
    output_format = _output_format(arguments)
    try:
        result, status = _dispatch(arguments)
    except ArchiveCreationError as error:
        _emit(error.report, output_format)
        return _report_exit_code(error.report)
    except StagingPolicyError as error:
        _emit_error("blocked", str(error), output_format)
        return _EXIT_POLICY
    except (
        OSError,
        ValueError,
        RuntimeError,
        StagingError,
        ScpOptionError,
        subprocess.SubprocessError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        _emit_error("error", f"运行错误: {type(error).__name__}: {error}", output_format)
        return _EXIT_RUNTIME

    _emit(result, output_format, status)
    return _status_exit_code(status)


def _dispatch(arguments: argparse.Namespace) -> tuple[Any, str]:
    handlers: dict[str, Callable[[argparse.Namespace], tuple[Any, str]]] = {
        "scan": _run_scan,
        "clean": _run_clean,
        "check-git": _run_check_git,
        "stage": _run_stage,
        "scp": _run_scp,
        "archive": _run_archive,
        "install-repo-guard": _run_install,
    }
    return handlers[arguments.command](arguments)


def _run_scan(arguments: argparse.Namespace) -> tuple[AuditReport, str]:
    report = scan_tree(arguments.path, include_xattrs=arguments.xattrs)
    return report, report.status


def _run_clean(arguments: argparse.Namespace) -> tuple[CleanupResult, str]:
    result = clean_tree(arguments.path, arguments.apply)
    if not arguments.apply:
        print("安全预览：未传入 --apply，不会删除任何文件。", file=sys.stderr)
    if result.errors or result.failed:
        return result, "error"
    if result.manual_review or (result.planned and not arguments.apply):
        return result, "blocked"
    return result, "passed"


def _run_check_git(arguments: argparse.Namespace) -> tuple[AuditReport, str]:
    report = check_git(arguments.repository, arguments.scope)
    return report, report.status


def _run_stage(arguments: argparse.Namespace) -> tuple[TransferManifest, str]:
    manifest = stage_tree(arguments.source, arguments.target)
    if arguments.manifest is not None:
        _write_manifest(arguments.manifest, manifest)
    return manifest, "passed"


def _run_scp(arguments: argparse.Namespace) -> tuple[ScpResult, str]:
    result = transfer_via_scp(
        arguments.source,
        arguments.destination,
        arguments.scp_option,
        arguments.scp_program,
        arguments.manifest_out,
    )
    return result, "passed" if result.returncode == 0 else "error"


def _run_archive(arguments: argparse.Namespace) -> tuple[Any, str]:
    limits = ArchiveLimits(
        max_members=arguments.max_members,
        max_total_uncompressed_bytes=arguments.max_total_bytes,
        max_member_uncompressed_bytes=arguments.max_member_bytes,
        max_compression_ratio=arguments.max_compression_ratio,
    )
    if arguments.archive_command == "create":
        output = create_archive(arguments.source, arguments.output, arguments.format, limits)
        return {"archive": str(output)}, "passed"
    report = verify_archive(arguments.archive, limits)
    return report, report.status


def _run_install(arguments: argparse.Namespace) -> tuple[Any, str]:
    result = install_repo_guard(
        arguments.repository,
        arguments.skill_root,
        arguments.ci,
        arguments.apply,
    )
    return result, "blocked" if result.failed or result.manual_review else "passed"


def _add_output_format(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--json", action="store_true", help="等价于 --format json")


def _add_archive_limit_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-members", type=int, default=100_000)
    parser.add_argument("--max-total-bytes", type=int, default=10 * 1024 * 1024 * 1024)
    parser.add_argument("--max-member-bytes", type=int, default=2 * 1024 * 1024 * 1024)
    parser.add_argument("--max-compression-ratio", type=float, default=1_000.0)


def _default_skill_root() -> Path:
    script_directory = Path(__file__).resolve().parent
    if (script_directory / "macos_hygiene_assets").is_dir():
        return script_directory
    return script_directory.parent


def _output_format(arguments: argparse.Namespace) -> str:
    return "json" if getattr(arguments, "json", False) else getattr(arguments, "format", "text")


def _write_manifest(path: Path, manifest: TransferManifest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_json_payload(manifest), encoding="utf-8")


def _emit(result: Any, output_format: str, status: str | None = None) -> None:
    if isinstance(result, AuditReport):
        print(render_json(result) if output_format == "json" else render_text(result))
        return
    payload = _result_payload(result, status or "passed")
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return
    print(f"状态: {payload['status']}")
    for key in sorted(item for item in payload if item != "status"):
        label = _TEXT_LABELS.get(key, key)
        print(f"{label}: {json.dumps(payload[key], ensure_ascii=False, sort_keys=True)}")


def _emit_error(status: str, message: str, output_format: str) -> None:
    payload = {"status": status, "errors": [message]}
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"运行错误: {message}", file=sys.stderr)


def _result_payload(result: Any, status: str) -> dict[str, Any]:
    if is_dataclass(result):
        payload = asdict(result)
    elif isinstance(result, dict):
        payload = dict(result)
    else:
        payload = {"result": str(result)}
    return {"status": status, "tool_version": TOOL_VERSION, **payload}


def _json_payload(value: Any) -> str:
    return json.dumps(asdict(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _status_exit_code(status: str) -> int:
    return {"passed": _EXIT_SUCCESS, "blocked": _EXIT_POLICY}.get(status, _EXIT_RUNTIME)


def _report_exit_code(report: AuditReport) -> int:
    return _status_exit_code(report.status)


if __name__ == "__main__":
    raise SystemExit(main())
