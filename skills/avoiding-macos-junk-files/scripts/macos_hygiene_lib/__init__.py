"""macOS 元数据治理公共接口。"""

from .archives import ArchiveCreationError, ArchiveLimits, create_archive, verify_archive
from .cleaner import clean_tree
from .git_guard import check_git
from .installer import InstallResult, install_repo_guard
from .model import AuditReport, Finding, Rule, TOOL_VERSION
from .reporting import render_json, render_text
from .scanner import scan_paths, scan_tree
from .staging import TransferManifest, stage_tree, transfer_via_scp

__all__ = (
    "AuditReport",
    "ArchiveCreationError",
    "ArchiveLimits",
    "Finding",
    "InstallResult",
    "Rule",
    "TransferManifest",
    "TOOL_VERSION",
    "check_git",
    "clean_tree",
    "create_archive",
    "install_repo_guard",
    "render_json",
    "render_text",
    "scan_paths",
    "scan_tree",
    "stage_tree",
    "transfer_via_scp",
    "verify_archive",
)
