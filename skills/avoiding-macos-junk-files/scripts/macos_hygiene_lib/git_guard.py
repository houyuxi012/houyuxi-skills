"""Git 工作区、索引和已跟踪文件的 macOS 元数据门禁。"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
from typing import Iterable

from .model import AuditReport, Finding
from .rules import ALL_RULES
from .scanner import scan_paths, scan_tree

_SCHEMA_VERSION = "1.1"
_SCOPES = frozenset({"worktree", "index", "tracked", "all"})
_GIT_PATH_COMMANDS = {
    "index": ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
    "tracked": ["ls-files", "-z"],
}


def run_git(repo: Path, args: list[str]) -> bytes:
    """运行 Git 命令并返回未经文本解码的标准输出。"""
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    return completed.stdout


def find_repository(path: Path | str) -> Path:
    """返回包含路径的 Git 仓库顶层目录，非仓库路径抛出运行错误。"""
    location = Path(path)
    try:
        output = run_git(location, ["rev-parse", "--show-toplevel"])
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"不是 Git 仓库: {location}") from error
    return Path(os.fsdecode(_remove_git_line_terminator(output)))


def git_paths(repo: Path | str, scope: str) -> list[str]:
    """以 NUL 分隔方式读取暂存区或已跟踪路径。"""
    if scope not in _GIT_PATH_COMMANDS:
        raise ValueError(f"git_paths 不支持的范围: {scope}")
    output = run_git(Path(repo), _GIT_PATH_COMMANDS[scope])
    return [os.fsdecode(item) for item in output.split(b"\0") if item]


def check_git(repo: Path | str, scope: str) -> AuditReport:
    """审计 Git 仓库的工作区、索引或已跟踪文件。"""
    if scope not in _SCOPES:
        raise ValueError(f"不支持的 Git 审计范围: {scope}")

    repository = find_repository(repo)
    started_at = _utc_timestamp()
    reports: list[AuditReport] = []

    if scope in {"worktree", "all"}:
        reports.append(_scan_worktree(repository))
    if scope in {"index", "all"}:
        reports.append(_scan_git_paths(repository, git_paths(repository, "index")))
    if scope in {"tracked", "all"}:
        reports.append(_scan_git_paths(repository, git_paths(repository, "tracked")))

    findings = _deduplicated_findings(reports)
    errors = [error for report in reports for error in report.errors]
    return AuditReport(
        schema_version=_SCHEMA_VERSION,
        operation="check_git",
        target=str(repository),
        status="error" if errors else "blocked" if findings else "passed",
        started_at=started_at,
        finished_at=_utc_timestamp(),
        findings=findings,
        errors=errors,
    )


def configure_hooks_path(repo: Path | str) -> None:
    """将仓库本地 hooks 路径固定为受版本控制的 .githooks 目录。"""
    run_git(Path(repo), ["config", "--local", "core.hooksPath", ".githooks"])


def _scan_worktree(repo: Path) -> AuditReport:
    report = scan_tree(repo, excluded_directory_names={".git"})
    findings = [
        finding
        for finding in report.findings
        if not _is_git_internal_path(finding.relative_path)
    ]
    return AuditReport(
        schema_version=report.schema_version,
        operation=report.operation,
        target=report.target,
        status="error" if report.errors else "blocked" if findings else "passed",
        started_at=report.started_at,
        finished_at=report.finished_at,
        findings=findings,
        errors=report.errors,
    )


def _scan_git_paths(repo: Path, paths: list[str]) -> AuditReport:
    report = scan_paths(repo, paths)
    findings = list(report.findings)
    if not report.errors:
        findings.extend(_path_component_findings(paths))
    return AuditReport(
        schema_version=report.schema_version,
        operation=report.operation,
        target=report.target,
        status="error" if report.errors else "blocked" if findings else "passed",
        started_at=report.started_at,
        finished_at=report.finished_at,
        findings=_sorted_unique_findings(findings),
        errors=report.errors,
    )


def _path_component_findings(paths: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for raw_path in paths:
        relative_path = Path(raw_path)
        if not _is_normalized_relative_path(relative_path):
            continue
        for component in relative_path.parts:
            for rule in ALL_RULES:
                if component in rule.exact_names or component.startswith(rule.prefixes):
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            relative_path=relative_path.as_posix(),
                            action=rule.action,
                        )
                    )
                    break
    return findings


def _deduplicated_findings(reports: list[AuditReport]) -> list[Finding]:
    return _sorted_unique_findings(
        finding for report in reports for finding in report.findings
    )


def _sorted_unique_findings(findings: Iterable[Finding]) -> list[Finding]:
    unique = {
        (finding.relative_path, finding.rule_id): finding
        for finding in findings
    }
    return sorted(unique.values(), key=lambda item: (item.relative_path, item.rule_id))


def _is_git_internal_path(relative_path: str) -> bool:
    return relative_path == ".git" or relative_path.startswith(".git/")


def _is_normalized_relative_path(path: Path) -> bool:
    return not path.is_absolute() and ".." not in path.parts


def _remove_git_line_terminator(output: bytes) -> bytes:
    if not output.endswith(b"\n"):
        return output
    record = output[:-1]
    return record[:-1] if record.endswith(b"\r") else record


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
