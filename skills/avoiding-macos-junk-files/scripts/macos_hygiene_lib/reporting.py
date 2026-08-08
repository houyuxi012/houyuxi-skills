"""macOS 元数据审计报告渲染器。"""

from __future__ import annotations

from dataclasses import asdict
import json

from .model import AuditReport


def render_json(report: AuditReport) -> str:
    """以稳定键排序输出 JSON 报告。"""
    return json.dumps(asdict(report), ensure_ascii=False, sort_keys=True, indent=2)


def render_text(report: AuditReport) -> str:
    """以便于命令行阅读的稳定顺序输出文本报告。"""
    lines = [
        f"架构版本: {report.schema_version}",
        f"操作: {report.operation}",
        f"目标: {report.target}",
        f"状态: {report.status}",
        f"开始时间: {report.started_at}",
        f"结束时间: {report.finished_at}",
    ]
    for finding in sorted(
        report.findings,
        key=lambda item: (item.rule_id, item.relative_path, item.detail or ""),
    ):
        lines.append(
            "发现项: "
            f"规则编号={finding.rule_id} 严重性={finding.severity} "
            f"处置={finding.action} 路径={finding.relative_path}"
            + (f" 详情={finding.detail}" if finding.detail else "")
        )
    for error in sorted(report.errors):
        lines.append(f"错误: {error}")
    return "\n".join(lines)
