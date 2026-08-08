"""面向传输的无 macOS 元数据暂存与完整性清单。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Literal

from .model import TOOL_VERSION
from .rules import ALL_RULES
from .scanner import scan_tree

_COPY_BUFFER_SIZE = 1024 * 1024
_MANIFEST_FILENAME = "transfer-manifest.json"
_SCP_OPTIONS_WITH_VALUE = frozenset({"-P", "-i", "-J", "-o"})
_SCP_FLAG_OPTIONS = frozenset({"-C", "-p", "-q"})
_SECURE_SCP_BASELINE = (
    "-F",
    "/dev/null",
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=yes",
)
_ALLOWED_SSH_OPTION_KEYS = frozenset(
    {
        "addressfamily",
        "batchmode",
        "compression",
        "connectionattempts",
        "connecttimeout",
        "identitiesonly",
        "ipqos",
        "loglevel",
        "serveralivecountmax",
        "serveraliveinterval",
        "stricthostkeychecking",
        "userknownhostsfile",
    }
)


class StagingPolicyError(RuntimeError):
    """暂存输入违反必须人工处置的安全策略。"""

    def __init__(self, violations: list[str]) -> None:
        self.violations = tuple(sorted(violations))
        super().__init__(f"暂存策略违规: {', '.join(self.violations)}")


class StagingError(RuntimeError):
    """暂存或复检无法安全完成。"""


class ScpOptionError(ValueError):
    """SCP 参数不在显式安全白名单内。"""


@dataclass(frozen=True)
class ManifestEntry:
    relative_path: str
    size: int
    sha256: str
    file_type: Literal["file", "directory", "symlink"]


@dataclass
class TransferManifest:
    source: str
    target: str
    entries: list[ManifestEntry] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    tool_version: str = TOOL_VERSION


@dataclass(frozen=True)
class ScpResult:
    returncode: int
    command: tuple[str, ...]
    stdout: str
    stderr: str
    manifest_path: str


def run_scp(
    staged_source: Path | str,
    destination: str,
    options: list[str] | tuple[str, ...],
    scp_program: Path | str,
) -> ScpResult:
    """以只读的私有发送快照执行 SCP，绝不把调用方目录交给外部进程。"""
    source_path = Path(staged_source)
    validated_options = _validated_scp_options(options)
    executable = _resolve_scp_program(scp_program)
    _validate_operand(destination, "SCP 目标")
    manifest_path = source_path / _MANIFEST_FILENAME
    audit_manifest_path = str(manifest_path) if manifest_path.is_file() else ""

    with tempfile.TemporaryDirectory(prefix="macos-hygiene-scp-send-") as temporary:
        private_parent = Path(temporary)
        parent_descriptor = _open_directory(private_parent)
        try:
            snapshot = private_parent / "payload"
            stage_tree(source_path, snapshot)
            snapshot_descriptor = _open_child_directory(
                parent_descriptor,
                "payload",
                Path("payload"),
            )
            try:
                _verify_directory_from_fd(snapshot_descriptor, Path("."), False)
                with _frozen_send_snapshot(parent_descriptor, snapshot_descriptor):
                    # 冻结之后以同一 FD 链进行最后复检；子进程继承父目录 FD。
                    _verify_directory_from_fd(snapshot_descriptor, Path("."), False)
                    # Darwin 的 /dev/fd 不能对目录 FD 继续路径解析；子进程在
                    # exec 前仅 fchdir 到保持打开的私有父目录 FD，payload 为稳定相对源。
                    stable_source = "payload"
                    execution_command = (
                        executable,
                        *_SECURE_SCP_BASELINE,
                        *validated_options,
                        "-r",
                        stable_source,
                        destination,
                    )
                    completed = subprocess.run(
                        list(execution_command),
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        shell=False,
                        pass_fds=(parent_descriptor,),
                        preexec_fn=lambda: os.fchdir(parent_descriptor),
                    )
            finally:
                os.close(snapshot_descriptor)
        finally:
            os.close(parent_descriptor)
        audit_command = (
            executable,
            *_SECURE_SCP_BASELINE,
            *_redacted_scp_options(validated_options),
            "-r",
            "payload",
            destination,
        )
        return ScpResult(
            returncode=completed.returncode,
            command=audit_command,
            stdout=completed.stdout,
            stderr=completed.stderr,
            manifest_path=audit_manifest_path,
        )


def transfer_via_scp(
    source: Path | str,
    destination: str,
    options: list[str] | tuple[str, ...],
    scp_program: Path | str,
    manifest_out: Path | str | None = None,
) -> ScpResult:
    """暂存、复检后通过 SCP 传输，并按请求持久化审计清单。"""
    with tempfile.TemporaryDirectory(prefix="macos-hygiene-scp-") as temporary:
        staged_source = Path(temporary) / "payload"
        manifest = stage_tree(source, staged_source)
        manifest_path = staged_source / _MANIFEST_FILENAME
        manifest_path.write_text(_manifest_payload(manifest), encoding="utf-8")
        recheck = scan_tree(staged_source)
        if recheck.errors:
            raise StagingError("; ".join(recheck.errors))
        if recheck.findings:
            raise StagingPolicyError(
                [finding.relative_path for finding in recheck.findings]
            )
        _verify_staged_manifest(staged_source, manifest)
        persistent_manifest = (
            _persist_manifest(Path(manifest_out), manifest)
            if manifest_out is not None
            else None
        )
        result = run_scp(staged_source, destination, options, scp_program)
        return ScpResult(
            returncode=result.returncode,
            command=result.command,
            stdout=result.stdout,
            stderr=result.stderr,
            manifest_path=str(persistent_manifest) if persistent_manifest else "",
        )


def _manifest_payload(manifest: TransferManifest) -> str:
    return json.dumps(asdict(manifest), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _persist_manifest(path: Path, manifest: TransferManifest) -> Path:
    """以原子替换写入调用方指定的审计清单，避免半写入证据。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(_manifest_payload(manifest))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except OSError:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise
    return path


def stage_tree(source: Path | str, target: Path | str) -> TransferManifest:
    """按内容复制普通文件，并排除可自动清理的 macOS 元数据。"""
    source_path = Path(source)
    target_path = Path(target)
    source_descriptor = _open_directory(source_path)
    target_parent_descriptor: int | None = None
    target_descriptor: int | None = None
    try:
        target_parent_descriptor, target_name = _open_target_parent(target_path)
        if _directory_is_source_or_descendant(source_descriptor, target_parent_descriptor):
            raise StagingPolicyError([f"暂存目标不得位于源目录内: {target_path}"])
        # 从现在开始，预检与复制共享同一个源根 FD；不再基于 source 路径扫描或重开。
        _verify_directory_from_fd(source_descriptor, Path("."), True)
        try:
            os.mkdir(target_name, 0o700, dir_fd=target_parent_descriptor)
        except OSError as error:
            raise StagingError(
                f"无法创建暂存目标: {target_path}（错误码 {error.errno}）"
            ) from error
        target_descriptor = _open_child_directory(
            target_parent_descriptor,
            target_name,
            Path("."),
        )
        entries: list[ManifestEntry] = []
        excluded_paths: set[Path] = set()
        _stage_directory_from_fd(
            source_descriptor,
            target_descriptor,
            Path("."),
            entries,
            excluded_paths,
        )
        _restore_metadata(target_descriptor, os.fstat(source_descriptor))
        entries.sort(key=lambda entry: entry.relative_path)
        return TransferManifest(
            source=str(source_path),
            target=str(target_path),
            entries=entries,
            excluded=sorted(path.as_posix() for path in excluded_paths),
        )
    finally:
        if target_descriptor is not None:
            os.close(target_descriptor)
        if target_parent_descriptor is not None:
            os.close(target_parent_descriptor)
        os.close(source_descriptor)


def _copy_symlink_from_fd(
    parent_descriptor: int,
    name: str,
    target_parent_descriptor: int,
    relative_path: Path,
) -> ManifestEntry:
    link_target = _read_stable_symlink(parent_descriptor, name, relative_path)
    if not _symlink_stays_within_root(relative_path, link_target):
        raise StagingPolicyError(
            [f"{relative_path.as_posix()} -> {link_target}"]
        )
    os.symlink(link_target, name, dir_fd=target_parent_descriptor)
    try:
        if not stat.S_ISLNK(os.lstat(name, dir_fd=target_parent_descriptor).st_mode):
            raise StagingError(f"暂存目标链接类型变化: {relative_path.as_posix()}")
    except OSError as error:
        raise StagingError(
            f"无法确认暂存目标链接: {relative_path.as_posix()}（错误码 {error.errno}）"
        ) from error
    encoded_target = os.fsencode(link_target)
    return ManifestEntry(
        relative_path=relative_path.as_posix(),
        size=len(encoded_target),
        sha256=hashlib.sha256(encoded_target).hexdigest(),
        file_type="symlink",
    )


def _copy_regular_file_from_fd(
    parent_descriptor: int,
    name: str,
    target_parent_descriptor: int,
    relative_path: Path,
) -> ManifestEntry:
    descriptor: int | None = None
    target_descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        source_stat = os.fstat(descriptor)
        if not stat.S_ISREG(source_stat.st_mode):
            raise StagingPolicyError(
                [f"复制时文件类型发生变化: {relative_path.as_posix()}"]
            )
        target_descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=target_parent_descriptor,
        )
        if not stat.S_ISREG(os.fstat(target_descriptor).st_mode):
            raise StagingError(f"暂存目标文件类型变化: {relative_path.as_posix()}")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, _COPY_BUFFER_SIZE):
            _write_all(target_descriptor, chunk)
            digest.update(chunk)
            size += len(chunk)
        os.fchmod(target_descriptor, stat.S_IMODE(source_stat.st_mode))
        os.utime(
            target_descriptor,
            ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns),
        )
        os.close(target_descriptor)
        target_descriptor = None
    except StagingPolicyError:
        raise
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise StagingPolicyError(
                [f"复制时检测到危险符号链接: {relative_path.as_posix()}"]
            ) from error
        raise StagingError(
            f"复制源文件失败: {relative_path.as_posix()}（错误码 {error.errno}）"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if target_descriptor is not None:
            os.close(target_descriptor)

    return ManifestEntry(
        relative_path=relative_path.as_posix(),
        size=size,
        sha256=digest.hexdigest(),
        file_type="file",
    )


def _open_directory(path: Path) -> int:
    """以不跟随链接的方式固定目录根，并验证其类型。"""
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise StagingPolicyError([f"目录不得为符号链接: {path}"]) from error
        raise StagingError(f"无法打开目录: {path}（错误码 {error.errno}）") from error
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise StagingError(f"不是目录: {path}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_child_directory(parent_descriptor: int, name: str, relative_path: Path) -> int:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise StagingPolicyError(
                [f"目录被替换为符号链接: {relative_path.as_posix()}"]
            ) from error
        raise StagingError(
            f"打开目录失败: {relative_path.as_posix()}（错误码 {error.errno}）"
        ) from error
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise StagingError(f"目录类型发生变化: {relative_path.as_posix()}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_target_parent(target_path: Path) -> tuple[int, str]:
    """以 nofollow 的目录 FD 链创建或打开目标父目录，绝不使用 mkdir(parents=True)。"""
    target_name = target_path.name
    if target_name in {"", ".", ".."}:
        raise StagingError(f"暂存目标名称无效: {target_path}")
    # macOS 的 /var 等系统路径本身可能是符号链接；先规范化调用方给出的
    # 目标父路径，再以 nofollow FD 链固定实际目录对象。
    parent_path = target_path.parent.resolve()
    if parent_path.is_absolute():
        descriptor = _open_directory(Path("/"))
        components = parent_path.parts[1:]
    else:
        descriptor = _open_directory(Path.cwd())
        components = parent_path.parts
    try:
        for component in components:
            if component in {"", "."}:
                continue
            if component == "..":
                raise StagingError(f"暂存目标父目录无效: {target_path}")
            try:
                os.mkdir(component, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            except OSError as error:
                raise StagingError(
                    f"无法创建目标父目录: {target_path}（错误码 {error.errno}）"
                ) from error
            child_descriptor = _open_child_directory(
                descriptor,
                component,
                Path(component),
            )
            os.close(descriptor)
            descriptor = child_descriptor
        return descriptor, target_name
    except BaseException:
        os.close(descriptor)
        raise


def _directory_is_source_or_descendant(source_descriptor: int, candidate_descriptor: int) -> bool:
    candidate_stat = os.fstat(candidate_descriptor)
    candidate_identity = (candidate_stat.st_dev, candidate_stat.st_ino)

    def visit(directory_descriptor: int) -> bool:
        current_stat = os.fstat(directory_descriptor)
        if (current_stat.st_dev, current_stat.st_ino) == candidate_identity:
            return True
        for name in os.listdir(directory_descriptor):
            node_stat = os.lstat(name, dir_fd=directory_descriptor)
            if not stat.S_ISDIR(node_stat.st_mode):
                continue
            child_descriptor = _open_child_directory(
                directory_descriptor,
                name,
                Path(name),
            )
            try:
                if visit(child_descriptor):
                    return True
            finally:
                os.close(child_descriptor)
        return False

    try:
        return visit(source_descriptor)
    except OSError as error:
        raise StagingError(
            f"无法验证暂存目标位置（错误码 {error.errno}）"
        ) from error


def _restore_metadata(descriptor: int, source_stat: os.stat_result) -> None:
    try:
        os.fchmod(descriptor, stat.S_IMODE(source_stat.st_mode))
        os.utime(
            descriptor,
            ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns),
        )
    except OSError as error:
        raise StagingError(f"无法恢复暂存元数据（错误码 {error.errno}）") from error


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("目标文件写入未前进")
        offset += written


def _stage_directory_from_fd(
    source_descriptor: int,
    target_descriptor: int,
    relative_directory: Path,
    entries: list[ManifestEntry],
    excluded_paths: set[Path],
) -> None:
    """以源/目标目录 FD 成对递归复制，读写两端均不重解析路径字符串。"""
    try:
        names = sorted(os.listdir(source_descriptor))
    except OSError as error:
        raise StagingError(
            f"读取源目录失败: {relative_directory.as_posix()}（错误码 {error.errno}）"
        ) from error

    for name in names:
        relative_path = relative_directory / name
        action = _action_for_name(name)
        if action == "manual_review":
            raise StagingPolicyError([relative_path.as_posix()])
        if action == "cleanable":
            excluded_paths.add(relative_path)
            continue
        try:
            source_stat = os.lstat(name, dir_fd=source_descriptor)
        except OSError as error:
            raise StagingError(
                f"读取源节点失败: {relative_path.as_posix()}（错误码 {error.errno}）"
            ) from error

        if stat.S_ISDIR(source_stat.st_mode):
            source_child_descriptor = _open_child_directory(
                source_descriptor,
                name,
                relative_path,
            )
            try:
                os.mkdir(name, 0o700, dir_fd=target_descriptor)
                target_child_descriptor = _open_child_directory(
                    target_descriptor,
                    name,
                    relative_path,
                )
                try:
                    child_stat = os.fstat(source_child_descriptor)
                    _stage_directory_from_fd(
                        source_child_descriptor,
                        target_child_descriptor,
                        relative_path,
                        entries,
                        excluded_paths,
                    )
                    _restore_metadata(target_child_descriptor, child_stat)
                finally:
                    os.close(target_child_descriptor)
                entries.append(
                    ManifestEntry(
                        relative_path=relative_path.as_posix(),
                        size=0,
                        sha256=hashlib.sha256(b"").hexdigest(),
                        file_type="directory",
                    )
                )
            finally:
                os.close(source_child_descriptor)
            continue
        if stat.S_ISLNK(source_stat.st_mode):
            entries.append(
                _copy_symlink_from_fd(
                    source_descriptor,
                    name,
                    target_descriptor,
                    relative_path,
                )
            )
            continue
        if stat.S_ISREG(source_stat.st_mode):
            entries.append(
                _copy_regular_file_from_fd(
                    source_descriptor,
                    name,
                    target_descriptor,
                    relative_path,
                )
            )
            continue
        raise StagingPolicyError([f"不支持的文件类型: {relative_path.as_posix()}"])


def _read_stable_symlink(parent_descriptor: int, name: str, relative_path: Path) -> str:
    """读取前后核对 inode，避免在检查与读取之间替换链接目标。"""
    try:
        before = os.lstat(name, dir_fd=parent_descriptor)
        link_target = os.readlink(name, dir_fd=parent_descriptor)
        after = os.lstat(name, dir_fd=parent_descriptor)
    except OSError as error:
        raise StagingError(
            f"读取符号链接失败: {relative_path.as_posix()}（错误码 {error.errno}）"
        ) from error
    if (
        not stat.S_ISLNK(before.st_mode)
        or not stat.S_ISLNK(after.st_mode)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise StagingError(f"符号链接在复制时发生变化: {relative_path.as_posix()}")
    return link_target


def _verify_safe_tree(root: Path, *, allow_cleanable: bool = False) -> None:
    descriptor = _open_directory(root)
    try:
        _verify_directory_from_fd(descriptor, Path("."), allow_cleanable)
    finally:
        os.close(descriptor)


def _verify_directory_from_fd(
    directory_descriptor: int,
    relative_directory: Path,
    allow_cleanable: bool,
) -> None:
    """复检冻结前后的发送树，不通过可被替换的字符串路径访问节点。"""
    try:
        names = sorted(os.listdir(directory_descriptor))
    except OSError as error:
        raise StagingError(
            f"发送快照复检无法读取目录 {relative_directory.as_posix()}（错误码 {error.errno}）"
        ) from error
    for name in names:
        relative_path = relative_directory / name
        action = _action_for_name(name)
        if action == "cleanable" and allow_cleanable:
            continue
        if action is not None:
            raise StagingPolicyError([relative_path.as_posix()])
        try:
            source_stat = os.lstat(name, dir_fd=directory_descriptor)
        except OSError as error:
            raise StagingError(
                f"发送快照复检时节点发生变化: {relative_path.as_posix()}（错误码 {error.errno}）"
            ) from error
        if stat.S_ISDIR(source_stat.st_mode):
            child_descriptor = _open_child_directory(
                directory_descriptor,
                name,
                relative_path,
            )
            try:
                _verify_directory_from_fd(
                    child_descriptor,
                    relative_path,
                    allow_cleanable,
                )
            finally:
                os.close(child_descriptor)
            continue
        if stat.S_ISLNK(source_stat.st_mode):
            link_target = _read_stable_symlink(
                directory_descriptor,
                name,
                relative_path,
            )
            if not _symlink_stays_within_root(relative_path, link_target):
                raise StagingPolicyError([f"{relative_path.as_posix()} -> {link_target}"])
            continue
        if stat.S_ISREG(source_stat.st_mode):
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=directory_descriptor,
                )
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise StagingError(
                        f"发送快照复检时文件类型变化: {relative_path.as_posix()}"
                    )
            except OSError as error:
                if error.errno == errno.ELOOP:
                    raise StagingPolicyError(
                        [f"发送快照含危险符号链接: {relative_path.as_posix()}"]
                    ) from error
                raise StagingError(
                    f"发送快照复检时无法读取文件: {relative_path.as_posix()}（错误码 {error.errno}）"
                ) from error
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            continue
        raise StagingPolicyError([f"不支持的文件类型: {relative_path.as_posix()}"])


@contextmanager
def _frozen_send_snapshot(parent_descriptor: int, snapshot_descriptor: int):
    """以 FD 冻结并保持发送快照身份，避免任何字符串路径重绑定。"""
    directory_descriptors = _collect_directory_descriptors(snapshot_descriptor)
    parent_mode = stat.S_IMODE(os.fstat(parent_descriptor).st_mode)
    changed_descriptors: list[tuple[int, int]] = []
    parent_changed = False
    try:
        # 所有目录均使用 fchmod；即使上级目录被重命名，FD 仍指向原对象。
        for descriptor, mode in directory_descriptors:
            os.fchmod(descriptor, mode & ~0o222)
            changed_descriptors.append((descriptor, mode))
        os.fchmod(parent_descriptor, parent_mode & ~0o222)
        parent_changed = True
        yield
    finally:
        restoration_errors: list[OSError] = []
        if parent_changed:
            try:
                os.fchmod(parent_descriptor, parent_mode)
            except OSError as error:
                restoration_errors.append(error)
        for descriptor, mode in reversed(changed_descriptors):
            try:
                os.fchmod(descriptor, mode)
            except OSError as error:
                restoration_errors.append(error)
        # 临时发送快照即将清理，目录必须恢复可写；失败不掩盖原业务异常。
        for descriptor, _ in directory_descriptors:
            try:
                os.fchmod(descriptor, 0o700)
            except OSError:
                pass
        for descriptor, _ in directory_descriptors:
            if descriptor != snapshot_descriptor:
                os.close(descriptor)
        if restoration_errors:
            raise StagingError("发送快照权限恢复失败") from restoration_errors[0]


def _collect_directory_descriptors(root_descriptor: int) -> list[tuple[int, int]]:
    """返回仍保持打开状态的目录 FD，供冻结、复原和安全清理使用。"""
    descriptors = [(root_descriptor, stat.S_IMODE(os.fstat(root_descriptor).st_mode))]

    def visit(parent_descriptor: int, relative_directory: Path) -> None:
        try:
            names = os.listdir(parent_descriptor)
        except OSError as error:
            raise StagingError(
                f"发送快照冻结时读取目录失败: {relative_directory.as_posix()}（错误码 {error.errno}）"
            ) from error
        for name in names:
            relative_path = relative_directory / name
            source_stat = os.lstat(name, dir_fd=parent_descriptor)
            if not stat.S_ISDIR(source_stat.st_mode):
                continue
            child_descriptor = _open_child_directory(
                parent_descriptor,
                name,
                relative_path,
            )
            descriptors.append(
                (child_descriptor, stat.S_IMODE(os.fstat(child_descriptor).st_mode))
            )
            visit(child_descriptor, relative_path)

    try:
        visit(root_descriptor, Path("."))
        return descriptors
    except BaseException:
        for descriptor, _ in descriptors:
            if descriptor != root_descriptor:
                os.close(descriptor)
        raise


def _find_escaping_symlinks(
    source_root: Path,
    excluded_paths: set[Path],
) -> list[str]:
    violations: list[str] = []
    for directory, directory_names, file_names in os.walk(source_root, followlinks=False):
        current = Path(directory)
        relative_directory = current.relative_to(source_root)
        directory_names[:] = [
            name
            for name in directory_names
            if relative_directory / name not in excluded_paths
        ]
        for name in (*directory_names, *file_names):
            relative_path = relative_directory / name
            candidate = source_root / relative_path
            if stat.S_ISLNK(candidate.lstat().st_mode):
                link_target = os.readlink(candidate)
                if not _symlink_stays_within_root(relative_path, link_target):
                    violations.append(
                        f"{relative_path.as_posix()} -> {link_target}"
                    )
    return sorted(violations)


def _find_unsupported_nodes(
    source_root: Path,
    excluded_paths: set[Path],
) -> list[str]:
    violations: list[str] = []
    for directory, directory_names, file_names in os.walk(source_root, followlinks=False):
        current = Path(directory)
        relative_directory = current.relative_to(source_root)
        directory_names[:] = [
            name
            for name in directory_names
            if relative_directory / name not in excluded_paths
        ]
        for name in (*directory_names, *file_names):
            relative_path = relative_directory / name
            mode = (source_root / relative_path).lstat().st_mode
            if not (
                stat.S_ISREG(mode)
                or stat.S_ISDIR(mode)
                or stat.S_ISLNK(mode)
            ):
                violations.append(f"不支持的文件类型: {relative_path.as_posix()}")
    return sorted(violations)


def _symlink_stays_within_root(relative_path: Path, link_target: str) -> bool:
    target_path = Path(link_target)
    if target_path.is_absolute():
        return False
    normalized = Path(os.path.normpath(relative_path.parent / target_path))
    return not normalized.is_absolute() and ".." not in normalized.parts


def _action_for_name(name: str) -> Literal["cleanable", "manual_review"] | None:
    for rule in ALL_RULES:
        if name in rule.exact_names or name.startswith(rule.prefixes):
            if rule.action in {"cleanable", "manual_review"}:
                return rule.action
    return None


def _validated_scp_options(options: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if isinstance(options, (str, bytes)):
        raise ScpOptionError("SCP options 必须是参数列表")
    validated: list[str] = []
    index = 0
    while index < len(options):
        option = options[index]
        if not isinstance(option, str):
            raise ScpOptionError("SCP 参数必须是字符串")
        if option in _SCP_FLAG_OPTIONS:
            validated.append(option)
            index += 1
            continue
        if option in _SCP_OPTIONS_WITH_VALUE:
            if index + 1 >= len(options):
                raise ScpOptionError(f"SCP 参数缺少值: {option}")
            value = options[index + 1]
            if not isinstance(value, str):
                raise ScpOptionError(f"SCP 参数值必须是字符串: {option}")
            _validate_operand(value, f"SCP 参数值 {option}", allow_leading_dash=False)
            if option == "-o":
                _validate_ssh_option(value)
            validated.extend((option, value))
            index += 2
            continue
        raise ScpOptionError(f"不允许的 SCP 参数: {option}")
    return tuple(validated)


def _validate_ssh_option(value: str) -> None:
    if "=" not in value:
        raise ScpOptionError("SCP -o 参数必须使用 Key=Value 格式")
    key, option_value = value.split("=", 1)
    if not key or not option_value:
        raise ScpOptionError("SCP -o 参数必须使用非空 Key=Value 格式")
    normalized_key = key.casefold()
    if normalized_key not in _ALLOWED_SSH_OPTION_KEYS:
        raise ScpOptionError(f"不允许的 SCP -o 配置键: {key}")
    if normalized_key in {"batchmode", "stricthostkeychecking"} and option_value.casefold() != "yes":
        raise ScpOptionError(f"SCP -o {key} 仅允许安全值 yes")


def _resolve_scp_program(scp_program: Path | str) -> str:
    """在子进程 fchdir 前固定带路径分隔符的程序路径；裸命令保留 PATH 解析。"""
    program = os.fspath(scp_program)
    if not isinstance(program, str) or not program:
        raise ScpOptionError("SCP 程序路径无效")
    separators = {os.sep}
    if os.altsep:
        separators.add(os.altsep)
    if any(separator in program for separator in separators):
        return str(Path(program).resolve())
    return program


def _redacted_scp_options(options: tuple[str, ...]) -> tuple[str, ...]:
    redacted: list[str] = []
    index = 0
    while index < len(options):
        option = options[index]
        redacted.append(option)
        if option in _SCP_OPTIONS_WITH_VALUE:
            redacted.append("<redacted-path>" if option == "-i" else options[index + 1])
            index += 2
        else:
            index += 1
    return tuple(redacted)


def _validate_operand(
    value: str,
    label: str,
    *,
    allow_leading_dash: bool = False,
) -> None:
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ScpOptionError(f"{label} 无效")
    if not allow_leading_dash and value.startswith("-"):
        raise ScpOptionError(f"{label} 不得以 '-' 开头")


def _verify_staged_manifest(root: Path, manifest: TransferManifest) -> None:
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.name != _MANIFEST_FILENAME
    }
    expected_paths = {entry.relative_path for entry in manifest.entries}
    if actual_paths != expected_paths:
        raise StagingError("暂存复检失败: 文件集合与清单不一致")

    for entry in manifest.entries:
        candidate = root / entry.relative_path
        if entry.file_type == "directory":
            if not candidate.is_dir() or candidate.is_symlink():
                raise StagingError(f"暂存复检失败: 目录类型不一致: {entry.relative_path}")
            continue
        if entry.file_type == "symlink":
            if not candidate.is_symlink():
                raise StagingError(f"暂存复检失败: 链接类型不一致: {entry.relative_path}")
            payload = os.fsencode(os.readlink(candidate))
        else:
            if not candidate.is_file() or candidate.is_symlink():
                raise StagingError(f"暂存复检失败: 文件类型不一致: {entry.relative_path}")
            size, sha256 = _hash_file(candidate)
            if size != entry.size or sha256 != entry.sha256:
                raise StagingError(f"暂存复检失败: SHA-256 不一致: {entry.relative_path}")
            continue
        if len(payload) != entry.size or hashlib.sha256(payload).hexdigest() != entry.sha256:
            raise StagingError(f"暂存复检失败: SHA-256 不一致: {entry.relative_path}")


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as file:
        while chunk := file.read(_COPY_BUFFER_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()
