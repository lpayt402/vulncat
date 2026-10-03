"""Original Vulncat terminal art; presentation never enters protocol or report output."""

from __future__ import annotations

import secrets
import sys

NAME = "Vulncat"
FULL_NAME = "Vulnerability Concatenator"
BANNERS = (
    "   /\\_/\\\n  ( o.o )   Vulncat\n   > ^ <    Vulnerability Concatenator\n   /| |\\    boo. probably.",
    "   /\\_/\\\n  ( O.o )   Vulncat\n   > ^ <    Vulnerability Concatenator\n"
    "  (_| |_)   found a signal. sat on it.",
    "   /\\_/\\\n  ( -.- )   Vulncat\n   > ^ <    Vulnerability Concatenator\n"
    "   /   \\    concatenating. then napping.",
)


def launch_banner(argv: list[str]) -> None:
    """Choose art only for a human terminal launch; stdout remains data-only."""
    if any(option in argv for option in ("--quiet", "--no-cat", "mcp")):
        return
    if not all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)):
        return
    print(secrets.choice(BANNERS) + "\n", file=sys.stderr)
