"""
OriginTrace — radare2 helpers

radare2 is an optional system dependency: present in the production image,
usually absent on a developer machine. Extractors call these helpers instead
of spawning r2 blindly, so a missing binary degrades analysis rather than
breaking it.
"""
import logging
import shutil
from typing import Any, Optional

logger = logging.getLogger("origintrace.r2")


def r2_available() -> bool:
    """True when a radare2 executable is on PATH."""
    return bool(shutil.which("r2") or shutil.which("radare2"))


def open_r2(file_path: str) -> Optional[Any]:
    """Open ``file_path`` in radare2, or return None when r2 cannot be used."""
    if not r2_available():
        return None
    try:
        import r2pipe
    except ImportError:
        logger.warning("[r2] radare2 is installed but the r2pipe package is missing")
        return None
    return r2pipe.open(file_path)


def current_seek(r2: Any) -> int:
    """Return radare2's current seek address (0 when it cannot be read)."""
    try:
        return int(str(r2.cmd("s")).strip().split()[0], 16)
    except (ValueError, IndexError, AttributeError):
        return 0
