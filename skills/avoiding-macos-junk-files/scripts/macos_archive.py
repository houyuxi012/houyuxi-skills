#!/usr/bin/env python3
"""旧归档入口的兼容包装器；实际业务逻辑由 macos_hygiene 统一处理。"""

from __future__ import annotations

import sys
from typing import Sequence


def map_legacy_arguments(arguments: Sequence[str]) -> list[str]:
    """将旧入口映射为新 CLI 参数，保留清理操作的安全预览默认值。"""
    mapped = list(arguments)
    if len(mapped) >= 3 and mapped[0] == "create":
        return ["archive", "create", *mapped[1:]]
    if len(mapped) >= 2 and mapped[0] == "verify":
        return ["archive", "verify", *mapped[1:]]
    if len(mapped) >= 2 and mapped[0] == "clean":
        return mapped
    return mapped


def main(arguments: Sequence[str] | None = None) -> int:
    """调用统一 CLI；此包装器不创建子进程、不实现归档业务逻辑。"""
    raw_arguments = list(sys.argv[1:] if arguments is None else arguments)
    mapped_arguments = map_legacy_arguments(raw_arguments)
    if raw_arguments and raw_arguments[0] == "clean" and "--apply" not in raw_arguments:
        print("兼容入口默认执行安全预览；传入 --apply 后才会实际清理。", file=sys.stderr)
    try:
        from macos_hygiene import main as hygiene_main
    except ImportError as error:
        raise RuntimeError("统一 macos_hygiene CLI 尚未安装或不可用") from error
    return hygiene_main(mapped_arguments)


if __name__ == "__main__":
    raise SystemExit(main())
