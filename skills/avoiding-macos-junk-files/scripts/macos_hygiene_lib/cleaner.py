"""macOS 元数据的显式、安全清理实现。"""

from __future__ import annotations

from pathlib import Path
import shutil

from .model import CleanupResult
from .scanner import scan_tree

_MANUAL_REVIEW_SKIP_REASON = "包含需人工复核的后代"


def clean_tree(root: Path, apply: bool) -> CleanupResult:
    """扫描目录并在明确授权后仅删除可自动清理的发现项。"""
    root_path = Path(root)
    report = scan_tree(root_path)
    planned = tuple(
        finding.relative_path
        for finding in report.findings
        if finding.action == "cleanable"
    )
    manual_review = [
        finding.relative_path
        for finding in report.findings
        if finding.action == "manual_review"
    ]
    protected_paths = _paths_with_manual_review_descendants(planned, manual_review)
    result = CleanupResult(
        planned=list(planned),
        manual_review=manual_review,
        skipped=[
            f"{relative_path}: {_MANUAL_REVIEW_SKIP_REASON}"
            for relative_path in planned
            if relative_path in protected_paths
        ],
        errors=list(report.errors),
    )

    if not apply or result.errors:
        return result

    executable_paths = tuple(
        relative_path for relative_path in planned if relative_path not in protected_paths
    )
    for relative_path in sorted(executable_paths, key=_deletion_order, reverse=True):
        target = root_path / relative_path
        try:
            _remove(target)
        except OSError:
            result.failed.append(relative_path)
        else:
            result.removed.append(relative_path)

    return result


def _deletion_order(relative_path: str) -> tuple[int, str]:
    return len(Path(relative_path).parts), relative_path


def _paths_with_manual_review_descendants(
    planned: tuple[str, ...], manual_review: list[str]
) -> frozenset[str]:
    return frozenset(
        planned_path
        for planned_path in planned
        if any(_is_descendant(manual_path, planned_path) for manual_path in manual_review)
    )


def _is_descendant(candidate: str, ancestor: str) -> bool:
    candidate_parts = Path(candidate).parts
    ancestor_parts = Path(ancestor).parts
    return (
        len(candidate_parts) > len(ancestor_parts)
        and candidate_parts[: len(ancestor_parts)] == ancestor_parts
    )


def _remove(target: Path) -> None:
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.is_dir():
        shutil.rmtree(target)
    else:
        raise FileNotFoundError(target)
