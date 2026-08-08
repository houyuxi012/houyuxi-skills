"""macOS 元数据审计规则。"""

from .model import Rule

CLEANABLE_RULES = (
    Rule("MACOS_DS_STORE", frozenset({".DS_Store"}), action="cleanable"),
    Rule("MACOS_APPLEDOUBLE", prefixes=("._",), action="cleanable"),
    Rule("MACOS_ARCHIVE_DIR", frozenset({"__MACOSX", ".AppleDouble"}), action="cleanable"),
)

REVIEW_RULES = (
    Rule(
        "MACOS_SEMANTIC_MARKER",
        frozenset(
            {
                ".VolumeIcon.icns",
                ".com.apple.timemachine.donotpresent",
                ".DocumentRevisions-V100",
                ".Spotlight-V100",
                ".Trashes",
                ".fseventsd",
            }
        ),
        action="manual_review",
    ),
)

MACOS_XATTR_RULE = Rule("MACOS_XATTR", action="manual_review")

ALL_RULES = CLEANABLE_RULES + REVIEW_RULES
