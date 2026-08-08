"""创建并验证不含 macOS 元数据的可移植归档。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
import tempfile
from typing import Iterable, Literal
import zipfile
import zlib

from .model import AuditReport, Finding
from .rules import ALL_RULES
from .scanner import scan_tree
from .staging import StagingError, StagingPolicyError, stage_tree

_ARCHIVE_FORMATS = frozenset({"zip", "tar", "tar.gz"})
_COPY_BUFFER_SIZE = 1024 * 1024
_TAR_BLOCK_SIZE = 512
_TAR_EOA_SIZE = _TAR_BLOCK_SIZE * 2
_TAR_RECORD_SIZE = _TAR_BLOCK_SIZE * 20
_RATIO_UNCOMPRESSED_WINDOW = 64 * 1024
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_MACOS_ZIP_EXTRA_FIELD_IDS = frozenset({0x07C8, 0x2605, 0x2705, 0x2805, 0x334D, 0x4D63})


@dataclass(frozen=True)
class ArchiveLimits:
    """归档校验资源上限，防止目录表和解压缩炸弹耗尽资源。"""

    max_members: int = 100_000
    max_total_uncompressed_bytes: int = 10 * 1024 * 1024 * 1024
    max_member_uncompressed_bytes: int = 2 * 1024 * 1024 * 1024
    max_compression_ratio: float = 1_000.0


class ArchiveCreationError(RuntimeError):
    """源目录不符合安全归档策略，附带可审计报告。"""

    def __init__(self, report: AuditReport) -> None:
        self.report = report
        super().__init__("归档创建被安全策略阻止")


class ArchiveRuntimeError(RuntimeError):
    """归档路径、配置或 I/O 失败，调用方应按运行错误处理。"""


def create_archive(
    source: Path | str,
    output: Path | str,
    archive_format: str | None = None,
    limits: ArchiveLimits | None = None,
) -> Path:
    """创建无 macOS 元数据归档，并以同目录原子替换发布结果。"""
    source_path = Path(source)
    output_path = Path(output)
    resolved_limits = limits or ArchiveLimits()
    try:
        normalized_format = _normalize_archive_format(archive_format, output_path)
        _validate_limits(resolved_limits)
        _ensure_output_is_safe(source_path, output_path)
    except (OSError, ValueError) as error:
        raise ArchiveRuntimeError(f"归档创建参数无效: {type(error).__name__}") from error
    source_report = scan_tree(source_path)
    blocking = [
        finding
        for finding in source_report.findings
        if finding.action == "manual_review"
    ]
    if source_report.errors or blocking:
        raise ArchiveCreationError(
            _make_report(
                "archive_create",
                source_path,
                blocking,
                source_report.errors,
                status="error" if source_report.errors else "blocked",
            )
        )

    output_parent = output_path.parent
    if not output_parent.is_dir():
        raise ArchiveRuntimeError(f"归档输出父目录不存在: {output_parent}")

    temporary_path: Path | None = None
    try:
        # 归档写入器会按路径重新打开成员，因此绝不可直接交给可变的源树。先通过
        # staging 的 dirfd/no-follow 复制固定内容，再仅从私有快照创建最终归档。
        with tempfile.TemporaryDirectory(prefix="macos-hygiene-archive-") as snapshot_root:
            snapshot_source = Path(snapshot_root) / "source"
            try:
                stage_tree(source_path, snapshot_source)
            except StagingPolicyError as error:
                refreshed_report = scan_tree(source_path)
                refreshed_blocking = [
                    finding
                    for finding in refreshed_report.findings
                    if finding.action == "manual_review"
                ]
                raise ArchiveCreationError(
                    _make_report(
                        "archive_create",
                        source_path,
                        refreshed_blocking
                        or [_finding("ARCHIVE_SOURCE_CHANGED", source_path.name)],
                        refreshed_report.errors,
                        status="error" if refreshed_report.errors else "blocked",
                    )
                ) from error
            except StagingError as error:
                raise ArchiveRuntimeError(
                    f"归档私有快照创建失败: {type(error).__name__}"
                ) from error

            with tempfile.NamedTemporaryFile(
                dir=output_parent,
                prefix=f".{output_path.name}.",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
            _write_archive(snapshot_source, temporary_path, normalized_format)
            verification = verify_archive(temporary_path, resolved_limits)
            if verification.status != "passed":
                raise ArchiveCreationError(verification)
            os.replace(temporary_path, output_path)
            temporary_path = None
            return output_path
    except ArchiveCreationError:
        raise
    except (OSError, tarfile.TarError, zipfile.BadZipFile, zlib.error) as error:
        raise ArchiveRuntimeError(f"归档创建失败: {type(error).__name__}") from error
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def verify_archive(path: Path | str, limits: ArchiveLimits) -> AuditReport:
    """验证归档结构、内容完整性和安全策略；绝不向调用方抛出归档异常。"""
    archive_path = Path(path)
    try:
        _validate_limits(limits)
        if not archive_path.is_file():
            return _make_report(
                "archive_verify",
                archive_path,
                [],
                [f"归档文件不存在或不是普通文件: {archive_path}"],
                status="error",
            )
        if zipfile.is_zipfile(archive_path) or _looks_like_zip(archive_path):
            return _verify_zip(archive_path, limits)
        if tarfile.is_tarfile(archive_path):
            return _verify_tar(archive_path, limits)
        return _make_report(
            "archive_verify",
            archive_path,
            [_finding("ARCHIVE_FORMAT", archive_path.name)],
            [],
            status="blocked",
        )
    except OSError as error:
        return _make_report(
            "archive_verify",
            archive_path,
            [],
            [f"归档校验运行失败: {type(error).__name__}"],
            status="error",
        )
    except (
        EOFError,
        RuntimeError,
        tarfile.TarError,
        zipfile.BadZipFile,
        zlib.error,
    ) as error:
        return _make_report(
                "archive_verify",
                archive_path,
                [_finding("ARCHIVE_INTEGRITY", archive_path.name)],
                [f"归档校验失败: {type(error).__name__}"],
                status="blocked",
        )
    except ValueError as error:
        return _make_report(
            "archive_verify",
            archive_path,
            [],
            [f"归档限制配置无效: {type(error).__name__}"],
            status="error",
        )


def _write_archive(source: Path, temporary: Path, archive_format: str) -> None:
    if archive_format == "zip":
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=False,
        ) as archive:
            for path, relative_path in _portable_source_members(source):
                if path.is_symlink():
                    raise OSError(f"不支持符号链接归档: {relative_path}")
                if path.is_dir():
                    archive.writestr(f"{relative_path.as_posix()}/", b"")
                elif path.is_file():
                    archive.write(path, arcname=relative_path.as_posix())
                else:
                    raise OSError(f"不支持的归档成员: {relative_path}")
        return

    mode = "w" if archive_format == "tar" else "w:gz"
    with tarfile.open(temporary, mode=mode, dereference=False) as archive:
        for path, relative_path in _portable_source_members(source):
            if path.is_symlink():
                raise OSError(f"不支持符号链接归档: {relative_path}")
            archive.add(path, arcname=relative_path.as_posix(), recursive=False)


def _portable_source_members(source: Path) -> Iterable[tuple[Path, Path]]:
    for directory, directory_names, file_names in os.walk(source, followlinks=False):
        current = Path(directory)
        directory_names[:] = sorted(
            name for name in directory_names if not _is_cleanable_name(name)
        )
        for name in (*directory_names, *sorted(file_names)):
            path = current / name
            relative_path = path.relative_to(source)
            rule = _rule_for_member(relative_path.as_posix())
            if rule is not None:
                if rule.action == "cleanable":
                    continue
                raise OSError(f"需人工复核的归档成员: {relative_path.as_posix()}")
            yield path, relative_path


def _verify_zip(path: Path, limits: ArchiveLimits) -> AuditReport:
    with zipfile.ZipFile(path, "r") as archive:
        members = archive.infolist()
        findings = _validate_zip_members(members, limits)
        if findings:
            return _blocked_report(path, findings)
        link_findings = _validate_zip_link_targets(archive, members)
        if link_findings:
            return _blocked_report(path, link_findings)
        corrupted_member = archive.testzip()
        if corrupted_member is not None:
            return _blocked_report(
                path,
                [_finding("ARCHIVE_INTEGRITY", corrupted_member)],
            )
    return _make_report("archive_verify", path, [], [], status="passed")


def _verify_tar(path: Path, limits: ArchiveLimits) -> AuditReport:
    member_count = 0
    total_size = 0
    verified_content_size = 0
    compressed_input = _is_gzip_archive(path)
    with path.open("rb") as source:
        raw_stream = _CountingReader(source)
        with tarfile.open(fileobj=raw_stream, mode="r|*") as archive:
            while (member := archive.next()) is not None:
                member_count += 1
                if member_count > limits.max_members:
                    return _blocked_report(
                        path,
                        [_finding("ARCHIVE_RESOURCE_LIMIT", member.name)],
                    )
                findings = _validate_tar_member(member, limits, total_size)
                if findings:
                    return _blocked_report(path, findings)
                if member.isreg():
                    total_size += member.size
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        return _blocked_report(
                            path,
                            [_finding("ARCHIVE_INTEGRITY", member.name)],
                        )
                    with extracted:
                        while chunk := extracted.read(_COPY_BUFFER_SIZE):
                            verified_content_size += len(chunk)
                            if compressed_input and _compression_ratio_exceeded(
                                verified_content_size,
                                raw_stream.bytes_read,
                                limits,
                            ):
                                return _blocked_report(
                                    path,
                                    [_finding("ARCHIVE_RESOURCE_LIMIT", member.name)],
                                )
    end_marker_finding = _verify_tar_stream_end(path, limits)
    if end_marker_finding is not None:
        return _blocked_report(path, [end_marker_finding])
    if (
        compressed_input
        and verified_content_size < _RATIO_UNCOMPRESSED_WINDOW
        and _exact_completed_gzip_ratio_exceeded(
            verified_content_size, path.stat().st_size, limits
        )
    ):
        return _blocked_report(
            path,
            [_finding("ARCHIVE_RESOURCE_LIMIT", path.name)],
        )
    return _make_report("archive_verify", path, [], [], status="passed")


def _validate_zip_members(
    members: list[zipfile.ZipInfo], limits: ArchiveLimits
) -> list[Finding]:
    findings: list[Finding] = []
    total_size = 0
    for count, member in enumerate(members, start=1):
        # ``ZipInfo.filename`` 会截断 NUL 后的名称；必须使用原始名称做策略判断。
        member_name = member.orig_filename
        findings.extend(_member_path_findings(member_name))
        member_type = stat.S_IFMT(member.external_attr >> 16)
        if member_type not in (0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK):
            findings.append(_finding("ARCHIVE_DANGEROUS_LINK", member_name))
        if count > limits.max_members:
            findings.append(_finding("ARCHIVE_RESOURCE_LIMIT", member_name))
        findings.extend(
            _zip_extra_field_findings(member)
        )
        findings.extend(
            _member_limit_findings(
                member_name,
                total_size,
                member.file_size,
                member.compress_size,
                limits,
            )
        )
        total_size += member.file_size
    return _unique_findings(findings)


def _zip_extra_field_findings(member: zipfile.ZipInfo) -> list[Finding]:
    """拒绝 AppleDouble/resource-fork/stream 的 ZIP extra 字段，并校验结构。"""
    extra = member.extra
    offset = 0
    findings: list[Finding] = []
    while offset < len(extra):
        if len(extra) - offset < 4:
            raise zipfile.BadZipFile("ZIP extra 字段头不完整")
        field_id, field_size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        if field_size > len(extra) - offset:
            raise zipfile.BadZipFile("ZIP extra 字段长度越界")
        if field_id in _MACOS_ZIP_EXTRA_FIELD_IDS:
            findings.append(_finding("MACOS_ZIP_EXTRA_FIELD", member.orig_filename))
        offset += field_size
    return findings


def _validate_zip_link_targets(
    archive: zipfile.ZipFile, members: list[zipfile.ZipInfo]
) -> list[Finding]:
    findings: list[Finding] = []
    for member in members:
        if not _zip_member_is_symlink(member):
            continue
        member_name = member.orig_filename
        try:
            target = archive.read(member).decode("utf-8")
        except UnicodeError:
            findings.append(_finding("ARCHIVE_DANGEROUS_LINK", member_name))
            continue
        if not _link_stays_in_archive(member_name, target, relative_to_member=True):
            findings.append(_finding("ARCHIVE_DANGEROUS_LINK", member_name))
    return _unique_findings(findings)


def _zip_member_is_symlink(member: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(member.external_attr >> 16)


def _validate_tar_member(
    member: tarfile.TarInfo,
    limits: ArchiveLimits,
    total_size: int,
) -> list[Finding]:
    findings = _member_path_findings(member.name)
    if _has_pax_xattr(member.pax_headers):
        findings.append(_finding("ARCHIVE_PAX_XATTR", member.name))
    if member.isreg():
        findings.extend(_member_limit_findings(
            member.name, total_size, member.size, None, limits
        ))
    elif member.issym():
        if not _link_stays_in_archive(member.name, member.linkname, relative_to_member=True):
            findings.append(_finding("ARCHIVE_DANGEROUS_LINK", member.name))
    elif member.islnk():
        if not _link_stays_in_archive(member.name, member.linkname, relative_to_member=False):
            findings.append(_finding("ARCHIVE_DANGEROUS_LINK", member.name))
    elif not member.isdir():
        findings.append(_finding("ARCHIVE_DANGEROUS_LINK", member.name))
    return _unique_findings(findings)


def _member_limit_findings(
    member_name: str,
    total_size: int,
    member_size: int,
    compressed_size: int | None,
    limits: ArchiveLimits,
) -> list[Finding]:
    if member_size > limits.max_member_uncompressed_bytes:
        return [_finding("ARCHIVE_RESOURCE_LIMIT", member_name)]
    if total_size + member_size > limits.max_total_uncompressed_bytes:
        return [_finding("ARCHIVE_RESOURCE_LIMIT", member_name)]
    if compressed_size is not None and member_size:
        ratio = float("inf") if compressed_size == 0 else member_size / compressed_size
        if ratio > limits.max_compression_ratio:
            return [_finding("ARCHIVE_RESOURCE_LIMIT", member_name)]
    return []


def _looks_like_zip(path: Path) -> bool:
    """将 ZIP 扩展名或 ZIP 魔数的解析失败归类为完整性错误。"""
    if path.suffix.lower() == ".zip":
        return True
    with path.open("rb") as archive:
        return archive.read(4).startswith(b"PK")


def _has_pax_xattr(pax_headers: dict[str, str]) -> bool:
    """拒绝全部 PAX xattr 变体，避免不同 TAR 工具绕过 macOS 元数据策略。"""
    return any("xattr" in key.casefold() for key in pax_headers)


def _compression_ratio_exceeded(
    uncompressed_bytes: int,
    compressed_bytes_read: int,
    limits: ArchiveLimits,
) -> bool:
    # 仅使用已实际读取的内容，不使用 TAR 头中不可信的声明大小；64 KiB 前
    # 保留格式头和 gzip 缓冲余量，之后每个内容块均立即检查。
    if uncompressed_bytes < _RATIO_UNCOMPRESSED_WINDOW or not compressed_bytes_read:
        return False
    return uncompressed_bytes / max(1, compressed_bytes_read) > limits.max_compression_ratio


def _exact_completed_gzip_ratio_exceeded(
    uncompressed_bytes: int,
    archive_bytes: int,
    limits: ArchiveLimits,
) -> bool:
    """小 gzip TAR 已完整读完后，以实际物理大小补做精确比率检查。"""
    return (
        uncompressed_bytes > 0
        and uncompressed_bytes / max(1, archive_bytes) > limits.max_compression_ratio
    )


def _verify_tar_stream_end(path: Path, limits: ArchiveLimits) -> Finding | None:
    """确认 TAR 两个 EOA 块，且 gzip 输入确实到达并验证了压缩流 EOF。"""
    if _is_gzip_archive(path):
        return _verify_gzip_tar_end(path, limits)
    if path.stat().st_size < _TAR_EOA_SIZE:
        return _finding("ARCHIVE_INTEGRITY", path.name)
    with path.open("rb") as archive:
        archive.seek(-_TAR_EOA_SIZE, os.SEEK_END)
        if archive.read(_TAR_EOA_SIZE) != b"\0" * _TAR_EOA_SIZE:
            return _finding("ARCHIVE_INTEGRITY", path.name)
    return None


def _is_gzip_archive(path: Path) -> bool:
    with path.open("rb") as source:
        return source.read(2) == b"\x1f\x8b"


def _verify_gzip_tar_end(path: Path, limits: ArchiveLimits) -> Finding | None:
    """完整读取 gzip 流以验证 trailer/CRC，并以受控预算限制第二次流式读取。"""
    decoded_size = 0
    tail = b""
    budget = (
        limits.max_total_uncompressed_bytes
        + limits.max_members * _TAR_BLOCK_SIZE
        + _TAR_EOA_SIZE
        + _TAR_RECORD_SIZE
    )
    with gzip.open(path, "rb") as archive:
        while chunk := archive.read(_COPY_BUFFER_SIZE):
            decoded_size += len(chunk)
            if decoded_size > budget:
                return _finding("ARCHIVE_RESOURCE_LIMIT", path.name)
            tail = (tail + chunk)[-_TAR_EOA_SIZE:]
    if len(tail) < _TAR_EOA_SIZE or tail != b"\0" * _TAR_EOA_SIZE:
        return _finding("ARCHIVE_INTEGRITY", path.name)
    return None


class _CountingReader:
    """仅包装流式 TAR 解码所需的 read，记录已消耗的原始输入字节。"""

    def __init__(self, source) -> None:
        self._source = source
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        result = self._source.read(size)
        self.bytes_read += len(result)
        return result

    def __getattr__(self, name: str):
        return getattr(self._source, name)


def _member_path_findings(member_name: str) -> list[Finding]:
    if not _is_safe_relative_member_path(member_name):
        return [_finding("ARCHIVE_PATH_TRAVERSAL", member_name)]
    rule = _rule_for_member(member_name)
    return [] if rule is None else [_finding(rule.rule_id, member_name)]


def _link_stays_in_archive(
    member_name: str,
    link_target: str,
    *,
    relative_to_member: bool,
) -> bool:
    if not _is_safe_relative_member_path(member_name):
        return False
    if not _is_safe_link_target(link_target):
        return False
    target_parts = _portable_parts(link_target)
    base_parts = _portable_parts(member_name)[:-1] if relative_to_member else []
    resolved: list[str] = list(base_parts)
    for part in target_parts:
        if part == ".":
            continue
        if part == "..":
            if not resolved:
                return False
            resolved.pop()
        else:
            resolved.append(part)
    return bool(resolved) or link_target in (".", "./")


def _is_safe_relative_member_path(value: str) -> bool:
    if not value or "\x00" in value or value.startswith(("/", "\\")):
        return False
    if _WINDOWS_DRIVE.match(value):
        return False
    parts = _portable_parts(value)
    return bool(parts) and all(part not in ("", ".", "..") for part in parts)


def _is_safe_link_target(value: str) -> bool:
    if not value or "\x00" in value or value.startswith(("/", "\\")):
        return False
    if _WINDOWS_DRIVE.match(value):
        return False
    return all(part != "" for part in _portable_parts(value))


def _portable_parts(value: str) -> tuple[str, ...]:
    # 将 Windows 分隔符按路径分隔符处理，避免 ``..\\`` 绕过检查。
    normalized = value.replace("\\", "/")
    return tuple(part for part in PurePosixPath(normalized).parts if part != "/")


def _rule_for_member(member_name: str):
    for component in _portable_parts(member_name):
        for rule in ALL_RULES:
            if component in rule.exact_names or component.startswith(rule.prefixes):
                return rule
    return None


def _is_cleanable_name(name: str) -> bool:
    rule = _rule_for_member(name)
    return rule is not None and rule.action == "cleanable"


def _normalize_archive_format(value: str | None, output: Path) -> Literal["zip", "tar", "tar.gz"]:
    candidate = value.lower() if value is not None else _format_from_output(output)
    aliases = {"tgz": "tar.gz"}
    candidate = aliases.get(candidate, candidate)
    if candidate not in _ARCHIVE_FORMATS:
        raise ValueError(f"不支持的归档格式: {value or output.suffix}")
    return candidate  # type: ignore[return-value]


def _format_from_output(output: Path) -> str:
    lower_name = output.name.lower()
    if lower_name.endswith(".tar.gz") or lower_name.endswith(".tgz"):
        return "tar.gz"
    if lower_name.endswith(".tar"):
        return "tar"
    if lower_name.endswith(".zip"):
        return "zip"
    raise ValueError(f"无法从输出路径推断归档格式: {output}")


def _ensure_output_is_safe(source: Path, output: Path) -> None:
    if not source.exists() or not source.is_dir():
        raise ValueError(f"归档源目录无效: {source}")
    try:
        output.resolve().relative_to(source.resolve())
    except ValueError:
        return
    raise ValueError("归档输出不得位于源目录内")


def _validate_limits(limits: ArchiveLimits) -> None:
    if (
        limits.max_members < 1
        or limits.max_total_uncompressed_bytes < 0
        or limits.max_member_uncompressed_bytes < 0
        or limits.max_compression_ratio <= 0
    ):
        raise ValueError("归档资源上限必须为正数")


def _finding(rule_id: str, relative_path: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity="error",
        relative_path=relative_path,
        action="blocked",
    )


def _unique_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        set(findings), key=lambda item: (item.relative_path, item.rule_id)
    )


def _blocked_report(path: Path, findings: list[Finding]) -> AuditReport:
    return _make_report("archive_verify", path, findings, [], status="blocked")


def _make_report(
    operation: str,
    target: Path,
    findings: list[Finding],
    errors: list[str],
    *,
    status: Literal["passed", "blocked", "error"],
) -> AuditReport:
    now = _timestamp()
    return AuditReport(
        schema_version="1.1",
        operation=operation,
        target=str(target),
        status=status,
        started_at=now,
        finished_at=now,
        findings=_unique_findings(findings),
        errors=sorted(errors),
    )


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
