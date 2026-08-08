"""macOS 元数据审计的数据模型。"""

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["error", "warning"]
Action = Literal["blocked", "cleanable", "manual_review"]
TOOL_VERSION = "1.1.0"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    exact_names: frozenset[str] = frozenset()
    prefixes: tuple[str, ...] = ()
    severity: Severity = "error"
    action: Action = "blocked"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    relative_path: str
    action: Action
    detail: str | None = None


@dataclass
class AuditReport:
    schema_version: str
    operation: str
    target: str
    status: Literal["passed", "blocked", "error"]
    started_at: str
    finished_at: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    tool_version: str = TOOL_VERSION


@dataclass
class CleanupResult:
    """一次清理操作的可审计结果。"""

    planned: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    manual_review: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
