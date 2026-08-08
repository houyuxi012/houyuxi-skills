"""macOS 元数据的只读扫描实现。"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
from typing import Iterable

from .model import AuditReport, Finding, Rule
from .rules import ALL_RULES, MACOS_XATTR_RULE

_SCHEMA_VERSION = "1.1"


def scan_tree(
    root: Path | str,
    excluded_directory_names: Iterable[str] = (),
    *,
    include_xattrs: bool = False,
) -> AuditReport:
    """以一次不跟随符号链接的遍历审计目录树，可排除指定目录名。"""
    root_path = Path(root)
    excluded_names = frozenset(excluded_directory_names)
    started_at = _utc_timestamp()
    errors = _root_errors(root_path)
    findings: list[Finding] = []

    if not errors:
        for directory, directory_names, file_names in os.walk(
            root_path,
            followlinks=False,
            onerror=lambda error: errors.append(_walk_error_message(error)),
        ):
            current = Path(directory)
            directory_names[:] = [
                name for name in directory_names if name not in excluded_names
            ]
            for name in (*directory_names, *file_names):
                candidate = current / name
                finding = _finding_for_name(name, candidate, root_path)
                if finding is not None:
                    findings.append(finding)
                if include_xattrs:
                    _append_xattr_findings(candidate, root_path, findings, errors)

    return _report("scan_tree", root_path, started_at, findings, errors)


def scan_paths(
    root: Path | str,
    paths: Iterable[Path | str],
    *,
    include_xattrs: bool = False,
) -> AuditReport:
    """审计调用方给出的、相对仓库根目录的规范化路径。"""
    root_path = Path(root)
    started_at = _utc_timestamp()
    errors = _root_errors(root_path)
    findings: list[Finding] = []

    if not errors:
        seen: set[Path] = set()
        for raw_path in paths:
            relative_path = Path(raw_path)
            if not _is_normalized_relative_path(relative_path):
                errors.append(f"无效相对路径: {relative_path.as_posix()}")
                continue
            if relative_path in seen:
                continue
            seen.add(relative_path)

            candidate = root_path / relative_path
            if not candidate.exists() and not candidate.is_symlink():
                continue
            finding = _finding_for_name(candidate.name, candidate, root_path)
            if finding is not None:
                findings.append(finding)
            if include_xattrs:
                _append_xattr_findings(candidate, root_path, findings, errors)

    return _report("scan_paths", root_path, started_at, findings, errors)


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _root_errors(root: Path) -> list[str]:
    if not root.exists():
        return [f"根目录不存在: {root}"]
    if not root.is_dir():
        return [f"根目录不是目录: {root}"]
    return []


def _walk_error_message(error: OSError) -> str:
    location = error.filename or "未知位置"
    error_code = error.errno if error.errno is not None else "未知"
    return f"目录遍历失败（错误码 {error_code}）: {location}"


def _is_normalized_relative_path(path: Path) -> bool:
    return not path.is_absolute() and ".." not in path.parts


def _finding_for_name(name: str, path: Path, root: Path) -> Finding | None:
    for rule in ALL_RULES:
        if _matches(rule, name):
            return Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                relative_path=path.relative_to(root).as_posix(),
                action=rule.action,
            )
    return None


def _append_xattr_findings(
    path: Path,
    root: Path,
    findings: list[Finding],
    errors: list[str],
) -> None:
    try:
        attributes = _list_xattrs(path)
    except OSError as error:
        error_code = error.errno if error.errno is not None else "未知"
        errors.append(f"扩展属性读取失败（错误码 {error_code}）: {path}")
        return
    for attribute in sorted(attributes):
        if _is_transfer_relevant_macos_xattr(attribute):
            findings.append(
                Finding(
                    rule_id=MACOS_XATTR_RULE.rule_id,
                    severity=MACOS_XATTR_RULE.severity,
                    relative_path=path.relative_to(root).as_posix(),
                    action=MACOS_XATTR_RULE.action,
                    detail=attribute,
                )
            )


def _list_xattrs(path: Path) -> list[str]:
    """通过 macOS 系统工具读取属性名；不读取或输出属性值。"""
    try:
        completed = subprocess.run(
            ["xattr", str(path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
    except FileNotFoundError as error:
        raise OSError("当前环境不支持 xattr 扫描") from error
    if completed.returncode != 0:
        raise OSError(completed.stderr.strip() or "xattr 命令执行失败")
    return [line for line in completed.stdout.splitlines() if line]


def _is_transfer_relevant_macos_xattr(attribute: str) -> bool:
    """识别会进入归档或 AppleDouble 兼容载体的 macOS 载荷属性。"""
    return attribute in {
        "com.apple.FinderInfo",
        "com.apple.ResourceFork",
    } or attribute.startswith("com.apple.metadata:")


def _matches(rule: Rule, name: str) -> bool:
    return name in rule.exact_names or name.startswith(rule.prefixes)


def _report(
    operation: str,
    root: Path,
    started_at: str,
    findings: list[Finding],
    errors: list[str],
) -> AuditReport:
    sorted_findings = sorted(
        findings,
        key=lambda item: (item.relative_path, item.rule_id, item.detail or ""),
    )
    status = "error" if errors else "blocked" if sorted_findings else "passed"
    return AuditReport(
        schema_version=_SCHEMA_VERSION,
        operation=operation,
        target=str(root),
        status=status,
        started_at=started_at,
        finished_at=_utc_timestamp(),
        findings=sorted_findings,
        errors=errors,
    )
