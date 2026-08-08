"""macOS 元数据仓库门禁的幂等安装实现。"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from .git_guard import configure_hooks_path, find_repository, run_git


_CI_CHOICES = frozenset({"none", "github", "gitlab", "both"})
_GITIGNORE_BEGIN = "# BEGIN avoiding-macos-junk-files"
_GITIGNORE_END = "# END avoiding-macos-junk-files"
_GITHUB_WORKFLOW = ".github/workflows/macos-metadata-guard.yml"
_GITLAB_PRIMARY = ".gitlab-ci.yml"
_INSTALLED_ASSETS = Path("tools/macos_hygiene_assets/repo-guard")
_HOOKS_CONFIG_ACTION = "git config --local core.hooksPath .githooks"
_GITLAB_MANUAL_REVIEW = (
    ".gitlab-ci.yml: 现有主配置不是安装器受管模板；为避免创建未被引用的"
    " GitLab 门禁文件，安装已阻断。请人工将 macOS 元数据检查合并到主配置后重试。"
)

REQUIRED_RUNTIME_FILES: tuple[str, ...] = (
    "scripts/macos_hygiene.py",
    "scripts/macos_hygiene_lib/__init__.py",
    "scripts/macos_hygiene_lib/model.py",
    "scripts/macos_hygiene_lib/rules.py",
    "scripts/macos_hygiene_lib/scanner.py",
    "scripts/macos_hygiene_lib/reporting.py",
    "scripts/macos_hygiene_lib/cleaner.py",
    "scripts/macos_hygiene_lib/git_guard.py",
    "scripts/macos_hygiene_lib/staging.py",
    "scripts/macos_hygiene_lib/archives.py",
    "scripts/macos_hygiene_lib/installer.py",
)
_ASSET_FILENAMES: tuple[str, ...] = (
    "gitignore.block",
    "pre-commit",
    "github-actions.yml",
    "gitlab-ci.yml",
)


@dataclass
class InstallResult:
    """一次仓库门禁安装的可审计结果。"""

    planned: list[str] = field(default_factory=list)
    written: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    manual_review: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _FileSnapshot:
    target: Path
    content: bytes | None
    mode: int | None


def install_repo_guard(
    repo: Path, skill_root: Path, ci: str, apply: bool
) -> InstallResult:
    """预览或安装仓库级 macOS 元数据门禁。"""
    if ci not in _CI_CHOICES:
        raise ValueError(f"不支持的 CI 类型: {ci}")

    repository = find_repository(repo)
    root = Path(skill_root)
    sources = _source_files(root, ci)
    destinations = _destinations(repository, root, sources, ci)
    result = InstallResult(
        planned=[relative for relative, _ in destinations] + [_HOOKS_CONFIG_ACTION]
    )

    missing = [str(source) for source in sources if not source.is_file()]
    if missing:
        result.failed.extend(f"缺少安装源文件: {source}" for source in missing)
        return result

    if _gitlab_requires_manual_review(repository, root, ci):
        result.manual_review.append(_GITLAB_MANUAL_REVIEW)
        result.failed.append(_GITLAB_MANUAL_REVIEW)
        return result

    if not apply:
        return result

    conflicts = _destination_conflicts(repository, destinations)
    if conflicts:
        result.failed.extend(conflicts)
        return result

    snapshots = _snapshot_destinations(repository, destinations)
    previous_hooks_path = _hooks_path_value(repository)
    gitignore_source = _asset_root(root) / "gitignore.block"
    try:
        _install_gitignore(repository / ".gitignore", gitignore_source, result)
        _raise_if_install_failed(result)

        for relative_path, source in destinations:
            if relative_path == ".gitignore":
                continue
            mode = stat.S_IXUSR if relative_path == ".githooks/pre-commit" else None
            _install_text(repository / relative_path, source, relative_path, result, mode)
            _raise_if_install_failed(result)

        configure_hooks_path(repository)
    except (OSError, RuntimeError, subprocess.CalledProcessError):
        if not result.failed:
            result.failed.append(_HOOKS_CONFIG_ACTION)
        _rollback_install(repository, snapshots, previous_hooks_path, result)
    else:
        target_list = result.unchanged if previous_hooks_path == b".githooks" else result.written
        target_list.append(_HOOKS_CONFIG_ACTION)
    return result


def _raise_if_install_failed(result: InstallResult) -> None:
    if result.failed:
        raise OSError("安装写入失败")


def _snapshot_destinations(
    repository: Path, destinations: list[tuple[str, Path]]
) -> list[_FileSnapshot]:
    snapshots: list[_FileSnapshot] = []
    seen: set[Path] = set()
    for relative_path, _ in destinations:
        target = repository / relative_path
        if target in seen:
            continue
        seen.add(target)
        if target.exists() or target.is_symlink():
            snapshots.append(
                _FileSnapshot(
                    target=target,
                    content=target.read_bytes(),
                    mode=stat.S_IMODE(target.stat().st_mode),
                )
            )
        else:
            snapshots.append(_FileSnapshot(target=target, content=None, mode=None))
    return snapshots


def _rollback_install(
    repository: Path,
    snapshots: list[_FileSnapshot],
    previous_hooks_path: bytes | None,
    result: InstallResult,
) -> None:
    """尽力恢复安装前的文件与本地 Git 配置，绝不宣称半安装成功。"""
    rollback_errors: list[str] = []
    for snapshot in reversed(snapshots):
        try:
            if snapshot.content is None:
                if snapshot.target.exists() or snapshot.target.is_symlink():
                    snapshot.target.unlink()
            else:
                _atomic_write_bytes(snapshot.target, snapshot.content, snapshot.mode)
        except OSError as error:
            rollback_errors.append(f"{snapshot.target}: {error}")
    for snapshot in sorted(snapshots, key=lambda item: len(item.target.parts), reverse=True):
        _remove_empty_parents(snapshot.target.parent, repository)
    try:
        _restore_hooks_path(repository, previous_hooks_path)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        rollback_errors.append(f"{_HOOKS_CONFIG_ACTION}: {error}")
    result.written.clear()
    result.failed.extend(f"回滚失败: {error}" for error in rollback_errors)


def _remove_empty_parents(directory: Path, repository: Path) -> None:
    current = directory
    while current != repository:
        try:
            current.rmdir()
        except OSError:
            return
        current = current.parent


def _hooks_path_value(repository: Path) -> bytes | None:
    try:
        return run_git(repository, ["config", "--local", "--get", "core.hooksPath"]).rstrip(
            b"\r\n"
        )
    except subprocess.CalledProcessError:
        return None


def _restore_hooks_path(repository: Path, value: bytes | None) -> None:
    if value is None:
        completed = subprocess.run(
            ["git", "-C", str(repository), "config", "--local", "--unset-all", "core.hooksPath"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        if completed.returncode not in {0, 5}:
            raise RuntimeError("无法恢复 core.hooksPath")
        return
    run_git(repository, ["config", "--local", "core.hooksPath", os.fsdecode(value)])


def _source_files(skill_root: Path, ci: str) -> list[Path]:
    runtime_root = _runtime_root(skill_root)
    asset_root = _asset_root(skill_root)
    runtime_sources = [
        runtime_root / Path(relative_path).relative_to("scripts")
        for relative_path in REQUIRED_RUNTIME_FILES
    ]
    # 始终携带完整资产集：已安装工具可继续向下游仓库部署全部 CI 组合。
    return runtime_sources + [asset_root / filename for filename in _ASSET_FILENAMES]


def _destinations(
    repository: Path, skill_root: Path, sources: list[Path], ci: str
) -> list[tuple[str, Path]]:
    by_name = {source.name: source for source in sources}
    destinations: list[tuple[str, Path]] = [
        (".gitignore", by_name["gitignore.block"]),
        ("tools/macos_hygiene.py", by_name["macos_hygiene.py"]),
    ]
    library_root = _library_root(skill_root)
    library_sources = [source for source in sources if source.is_relative_to(library_root)]
    for source in library_sources:
        suffix = source.relative_to(library_root)
        destinations.append(((Path("tools/macos_hygiene_lib") / suffix).as_posix(), source))
    asset_root = _asset_root(skill_root)
    for source in sources:
        if source.is_relative_to(asset_root):
            destinations.append(((_INSTALLED_ASSETS / source.name).as_posix(), source))
    destinations.append((".githooks/pre-commit", by_name["pre-commit"]))
    if ci in {"github", "both"}:
        destinations.append((_GITHUB_WORKFLOW, by_name["github-actions.yml"]))
    if ci in {"gitlab", "both"}:
        destinations.append((_GITLAB_PRIMARY, by_name["gitlab-ci.yml"]))
    return destinations


def _runtime_root(skill_root: Path) -> Path:
    source_layout = skill_root / "scripts" / "macos_hygiene.py"
    return skill_root / "scripts" if source_layout.is_file() else skill_root


def _library_root(skill_root: Path) -> Path:
    return _runtime_root(skill_root) / "macos_hygiene_lib"


def _asset_root(skill_root: Path) -> Path:
    source_assets = skill_root / "assets" / "repo-guard"
    return source_assets if source_assets.is_dir() else skill_root / "macos_hygiene_assets" / "repo-guard"


def _gitlab_requires_manual_review(repository: Path, skill_root: Path, ci: str) -> bool:
    """拒绝向未受管的 GitLab 主配置旁写入不生效的 fallback 文件。"""
    if ci not in {"gitlab", "both"}:
        return False
    primary = repository / _GITLAB_PRIMARY
    if not primary.exists():
        return False
    template = _asset_root(skill_root) / "gitlab-ci.yml"
    try:
        return primary.read_text(encoding="utf-8") != template.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return True


def _destination_conflicts(
    repository: Path, destinations: list[tuple[str, Path]]
) -> list[str]:
    conflicts: list[str] = []
    for relative_path, source in destinations:
        target = repository / relative_path
        try:
            expected = source.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            conflicts.append(f"{relative_path}: 无法读取安装源文件: {error}")
            continue

        if relative_path == ".gitignore":
            try:
                existing = target.read_text(encoding="utf-8") if target.exists() else ""
                _merge_managed_block(existing, expected)
            except (OSError, UnicodeError, ValueError) as error:
                conflicts.append(f".gitignore: {error}")
            continue

        if not target.exists() and not target.is_symlink():
            continue
        if target.is_symlink() or not target.is_file():
            conflicts.append(f"{relative_path}: 目标文件冲突，现有目标不是普通文件")
            continue
        try:
            existing = target.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            conflicts.append(f"{relative_path}: 目标文件冲突，无法安全读取: {error}")
            continue
        if existing != expected:
            conflicts.append(
                f"{relative_path}: 目标文件冲突，现有内容不属于安装器受管内容"
            )
    return conflicts


def _install_gitignore(target: Path, source: Path, result: InstallResult) -> None:
    try:
        existing = target.read_text(encoding="utf-8") if target.exists() else ""
        managed_block = source.read_text(encoding="utf-8")
        desired = _merge_managed_block(existing, managed_block)
        changed = _write_if_changed(target, desired)
        (result.written if changed else result.unchanged).append(".gitignore")
    except (OSError, UnicodeError, ValueError) as error:
        result.failed.append(f".gitignore: {error}")


def _merge_managed_block(existing: str, managed_block: str) -> str:
    begin_count = existing.count(_GITIGNORE_BEGIN)
    end_count = existing.count(_GITIGNORE_END)
    block = managed_block.rstrip("\n") + "\n"
    if begin_count == 0 and end_count == 0:
        separator = "" if not existing or existing.endswith("\n") else "\n"
        return f"{existing}{separator}{block}"
    if begin_count != 1 or end_count != 1:
        raise ValueError("受管块标记缺失或重复")
    start = existing.index(_GITIGNORE_BEGIN)
    end = existing.index(_GITIGNORE_END, start) + len(_GITIGNORE_END)
    if end < start:
        raise ValueError("受管块标记顺序错误")
    suffix = existing[end:]
    if suffix.startswith("\n"):
        suffix = suffix[1:]
    return f"{existing[:start]}{block}{suffix}"


def _install_text(
    target: Path,
    source: Path,
    relative_path: str,
    result: InstallResult,
    add_mode: int | None,
) -> None:
    try:
        content = source.read_text(encoding="utf-8")
        mode_changed = bool(
            add_mode is not None
            and (not target.exists() or not target.stat().st_mode & add_mode)
        )
        content_changed = _write_if_changed(target, content)
        if add_mode is not None:
            target.chmod(target.stat().st_mode | add_mode)
        changed = content_changed or mode_changed
        (result.written if changed else result.unchanged).append(relative_path)
    except (OSError, UnicodeError) as error:
        result.failed.append(f"{relative_path}: {error}")


def _write_if_changed(target: Path, content: str) -> bool:
    if target.exists() and target.read_text(encoding="utf-8") == content:
        return False
    _atomic_write_text(target, content)
    return True


def _atomic_write_text(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target_mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o644
    _atomic_write_bytes(target, content.encode("utf-8"), target_mode)


def _atomic_write_bytes(target: Path, content: bytes, target_mode: int | None) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    resolved_mode = target_mode if target_mode is not None else 0o644
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=target.parent,
            prefix=f".{target.name}.",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.chmod(resolved_mode)
        os.replace(temporary_path, target)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _hooks_path_is_configured(repository: Path) -> bool:
    try:
        value = run_git(
            repository, ["config", "--local", "--get", "core.hooksPath"]
        )
    except subprocess.CalledProcessError:
        return False
    return value.rstrip(b"\r\n") == b".githooks"
