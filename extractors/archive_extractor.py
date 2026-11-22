"""
OriginTrace — Archive / Package Extractor

Unpacks software packages (PyPI wheels and sdists, npm tarballs, plain ZIP
and TAR archives) and runs the per-file extractors over the members that
matter for supply-chain analysis: install hooks first, then scripts, then
native binaries.

Archives are attacker-controlled, so unpacking is defensive by design:
  - Members are never written to their own paths. Each one is read into
    memory and analysed from a randomly named temp file, so a "../../x"
    member name cannot escape (no zip-slip).
  - Every member read is size-capped, and the number of members, the
    bytes walked and the wall-clock time are all bounded (no zip bombs).
  - Symlinks, devices and other non-regular tar members are ignored.
  - Nested archives are reported, not recursed into.
"""
import gzip
import hashlib
import json
import logging
import os
import re
import tarfile
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

logger = logging.getLogger("origintrace.archive_extractor")

# --- Limits (module-level so deployments and tests can tune them) ---
MAX_MEMBERS_LISTED = 5000
MAX_MEMBERS_ANALYZED = 40
MAX_BINARY_MEMBERS = 3           # binaries are far costlier to analyse than scripts
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_LISTED_BYTES = 512 * 1024 * 1024   # stop walking a tar stream beyond this
ANALYSIS_BUDGET_SECONDS = 60.0
MAX_NOTES = 25

MAX_MEMBER_ITEMS = 25            # per-member cap on calls / strings / imports
MAX_MEMBER_BLOBS = 3
MAX_SOURCE_EXCERPT_CHARS = 1500
MAX_AGGREGATE_ITEMS = 200

SCRIPT_EXTENSIONS = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".ps1", ".psm1", ".bat", ".cmd", ".pth",
}
BINARY_EXTENSIONS = {".exe", ".dll", ".so", ".pyd", ".node", ".dylib", ".elf", ".scr", ".sys"}
DOCUMENT_EXTENSIONS = {".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm", ".pptx"}
NESTED_EXTENSIONS = {".zip", ".whl", ".jar", ".egg", ".tgz", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".nupkg"}

# Files that run automatically when a package is installed or imported.
INSTALL_SCRIPT_NAMES = {"install.js", "preinstall.js", "postinstall.js", "install.sh", "setup.sh"}
NPM_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish")

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_HOOK_SCRIPT_RE = re.compile(r"[\w./\\-]+\.(?:js|cjs|mjs|sh|py)\b")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_READ_ERRORS = (OSError, EOFError, RuntimeError, NotImplementedError, zlib.error, zipfile.BadZipFile, tarfile.TarError)

# Callback that analyses one extracted member: (temp_path, basename) ->
# {"file_type": str, "features": dict | None}
MemberAnalyzer = Callable[[str, str], Dict[str, Any]]


@dataclass(frozen=True)
class _Entry:
    name: str
    size: int   # -1 when the container does not record it


def _normalize(name: str) -> str:
    return name.replace("\\", "/")


def _base(name: str) -> str:
    return _normalize(name).rsplit("/", 1)[-1]


def _ext(name: str) -> str:
    return os.path.splitext(_base(name))[1].lower()


def _depth(name: str) -> int:
    return _normalize(name).strip("/").count("/")


def _display_path(name: str) -> str:
    """Member path made safe to show: forward slashes, no control characters."""
    return _CONTROL_CHARS_RE.sub("", _normalize(name))[:240]


def _is_traversal(name: str) -> bool:
    normalized = _normalize(name)
    return normalized.startswith("/") or ".." in normalized.split("/") or bool(_DRIVE_RE.match(normalized))


def _unique(items: List[str], limit: int) -> List[str]:
    return list(dict.fromkeys(item for item in items if item))[:limit]


# ─── Container backends ──────────────────────────────────────

class _ZipBackend:
    archive_type = "zip"

    def __init__(self, file_path: str):
        self._zf = zipfile.ZipFile(file_path)
        self.truncated = False

    def entries(self) -> List[_Entry]:
        infos = self._zf.infolist()
        self.truncated = len(infos) > MAX_MEMBERS_LISTED
        return [_Entry(info.filename, info.file_size) for info in infos[:MAX_MEMBERS_LISTED] if not info.is_dir()]

    def read(self, names: Set[str], limit: int) -> Iterator[Tuple[str, Optional[bytes]]]:
        for info in self._zf.infolist():
            if info.filename not in names:
                continue
            data: Optional[bytes] = None
            if not info.flag_bits & 0x1:  # bit 0 = encrypted
                try:
                    with self._zf.open(info) as handle:
                        # Bounded read: the declared size cannot be trusted.
                        data = handle.read(limit + 1)
                except _READ_ERRORS as e:
                    logger.debug(f"[Archive] unreadable zip member {info.filename!r}: {e}")
            yield info.filename, data

    def close(self) -> None:
        self._zf.close()


class _TarBackend:
    archive_type = "tar"

    def __init__(self, file_path: str):
        self._path = file_path
        self.truncated = False

    def entries(self) -> List[_Entry]:
        entries: List[_Entry] = []
        walked = 0
        with tarfile.open(self._path, "r:*") as tar:
            for member in tar:
                if len(entries) >= MAX_MEMBERS_LISTED or walked > MAX_LISTED_BYTES:
                    self.truncated = True
                    break
                if member.isreg():  # ignore links, devices, directories
                    entries.append(_Entry(member.name, member.size))
                    walked += member.size
        return entries

    def read(self, names: Set[str], limit: int) -> Iterator[Tuple[str, Optional[bytes]]]:
        remaining = len(names)
        with tarfile.open(self._path, "r:*") as tar:
            for member in tar:
                if remaining <= 0:
                    break
                if not member.isreg() or member.name not in names:
                    continue
                remaining -= 1
                data: Optional[bytes] = None
                try:
                    handle = tar.extractfile(member)
                    if handle is not None:
                        data = handle.read(limit + 1)
                except _READ_ERRORS as e:
                    logger.debug(f"[Archive] unreadable tar member {member.name!r}: {e}")
                yield member.name, data

    def close(self) -> None:
        return None


class _GzipBackend:
    """A lone gzip stream (not a tarball): one member, size unknown."""
    archive_type = "gzip"

    def __init__(self, file_path: str, filename: str):
        self._path = file_path
        self._name = (filename[:-3] if filename.lower().endswith(".gz") else f"{filename}.out") or "payload"
        self.truncated = False

    def entries(self) -> List[_Entry]:
        return [_Entry(self._name, -1)]

    def read(self, names: Set[str], limit: int) -> Iterator[Tuple[str, Optional[bytes]]]:
        if self._name not in names:
            return
        data: Optional[bytes] = None
        try:
            with gzip.open(self._path) as handle:
                data = handle.read(limit + 1)
        except _READ_ERRORS as e:
            logger.debug(f"[Archive] unreadable gzip stream: {e}")
        yield self._name, data

    def close(self) -> None:
        return None


def _open_backend(file_path: str, filename: str) -> Any:
    if zipfile.is_zipfile(file_path):
        return _ZipBackend(file_path)
    try:
        is_tar = tarfile.is_tarfile(file_path)
    except _READ_ERRORS:
        is_tar = False
    if is_tar:
        return _TarBackend(file_path)
    with open(file_path, "rb") as handle:
        if handle.read(2) == b"\x1f\x8b":
            return _GzipBackend(file_path, filename)
    raise ValueError("unsupported or corrupt archive")


# ─── Package metadata ────────────────────────────────────────

def _find_metadata(entries: List[_Entry]) -> Dict[str, str]:
    """Locate package manifests: role -> member name (shallowest wins)."""
    roles: Dict[str, str] = {}
    for entry in sorted(entries, key=lambda e: (_depth(e.name), e.name)):
        normalized = _normalize(entry.name)
        base = _base(normalized)
        parent = normalized.rsplit("/", 1)[0] if "/" in normalized else ""
        if parent.endswith(".dist-info") and base == "METADATA":
            roles.setdefault("pypi", entry.name)
        elif parent.endswith(".dist-info") and base == "WHEEL":
            roles.setdefault("wheel", entry.name)
        elif base == "PKG-INFO" and (parent.endswith(".egg-info") or _depth(normalized) <= 1):
            roles.setdefault("pypi", entry.name)
        elif base == "package.json" and _depth(normalized) <= 1:
            roles.setdefault("npm", entry.name)
    return roles


def _parse_pypi_metadata(data: bytes) -> Optional[Dict[str, str]]:
    name = version = ""
    for line in data.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            break  # headers end at the first blank line
        key, _, value = line.partition(":")
        if key.strip().lower() == "name" and not name:
            name = value.strip()
        elif key.strip().lower() == "version" and not version:
            version = value.strip()
    if not name:
        return None
    return {"ecosystem": "PyPI", "name": name[:100], "version": version[:50]}


def _parse_npm_manifest(data: bytes) -> Tuple[Optional[Dict[str, str]], List[str]]:
    """Return (package identity, lifecycle hooks) from a package.json."""
    try:
        manifest = json.loads(data.decode("utf-8", errors="replace"))
    except ValueError:
        return None, []
    if not isinstance(manifest, dict):
        return None, []

    scripts = manifest.get("scripts")
    hooks = [
        f"{stage}: {scripts[stage]}"[:200]
        for stage in NPM_LIFECYCLE_SCRIPTS
        if isinstance(scripts, dict) and isinstance(scripts.get(stage), str)
    ]
    name = manifest.get("name")
    if not isinstance(name, str) or not name:
        return None, hooks
    version = manifest.get("version")
    return {"ecosystem": "npm", "name": name[:100], "version": str(version or "")[:50]}, hooks


# ─── Member selection ────────────────────────────────────────

def _priority(entry: _Entry, hook_scripts: Set[str]) -> int:
    """Higher runs first; 0 means "not worth analysing"."""
    base = _base(entry.name).lower()
    ext = _ext(base)
    if base == "setup.py":
        return 100
    if base in hook_scripts:
        return 95
    if base in INSTALL_SCRIPT_NAMES:
        return 90
    if ext == ".pth":
        return 85
    if base == "__init__.py":
        return 60
    if ext in SCRIPT_EXTENSIONS:
        return 40
    if ext in BINARY_EXTENSIONS:
        return 30
    if ext in DOCUMENT_EXTENSIONS:
        return 20
    return 0


def _member_record(path: str, data: bytes, file_type: str, features: Dict[str, Any]) -> Dict[str, Any]:
    """Compact, size-bounded summary of one analysed member."""
    record: Dict[str, Any] = {
        "path": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "file_type": file_type,
        "language": None,
        "imports": [],
        "suspicious_calls": [],
        "high_value_strings": [],
        "encoded_blobs": [],
        "obfuscation_score": 0.0,
        "has_macros": False,
        "source_excerpt": "",
    }
    if file_type == "script":
        record.update(
            language=features.get("language"),
            imports=_unique(features.get("ast_imports") or [], MAX_MEMBER_ITEMS),
            suspicious_calls=_unique(features.get("suspicious_calls") or [], MAX_MEMBER_ITEMS),
            high_value_strings=_unique(features.get("high_value_strings") or [], MAX_MEMBER_ITEMS),
            encoded_blobs=(features.get("encoded_blobs") or [])[:MAX_MEMBER_BLOBS],
            obfuscation_score=float(features.get("obfuscation_score") or 0.0),
            source_excerpt=str(features.get("raw_source") or "")[:MAX_SOURCE_EXCERPT_CHARS],
        )
        if _ext(path) == ".pth":
            # Lines starting with "import" in a .pth file run at interpreter startup.
            for line in data.decode("utf-8", errors="replace").splitlines():
                if line.startswith(("import ", "import\t")):
                    record["suspicious_calls"].append(f".pth startup code: {line[:80]}")
    elif file_type in ("pe", "elf"):
        record.update(
            imports=_unique(features.get("imports") or [], MAX_MEMBER_ITEMS),
            high_value_strings=_unique(features.get("high_value_strings") or [], MAX_MEMBER_ITEMS),
        )
    elif file_type == "document":
        record.update(
            suspicious_calls=_unique(features.get("suspicious_keywords") or [], MAX_MEMBER_ITEMS),
            high_value_strings=_unique(
                (features.get("high_value_strings") or []) + (features.get("embedded_urls") or []), MAX_MEMBER_ITEMS
            ),
            has_macros=bool(features.get("has_macros")),
            source_excerpt=str(features.get("macro_source") or "")[:MAX_SOURCE_EXCERPT_CHARS],
        )
    return record


class ArchiveExtractor:
    """Extraction pipeline for packages and archives."""

    def __init__(self, analyze_member: MemberAnalyzer):
        self._analyze_member = analyze_member

    def extract(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Unpack an archive and analyse its most relevant members.
        Returns a dict compatible with the ArchiveFeatures schema.

        Raises:
            ValueError: when the file is not a readable ZIP, TAR or gzip stream.
        """
        backend = _open_backend(file_path, filename)
        notes: List[str] = []
        try:
            entries = backend.entries()
            if backend.truncated:
                notes.append(f"archive listing truncated at {len(entries)} member(s)")

            # ── Package identity and install hooks ──
            roles = _find_metadata(entries)
            metadata = self._read(backend, set(roles.values()), MAX_METADATA_BYTES)
            package: Optional[Dict[str, str]] = None
            install_hooks: List[str] = []
            if "npm" in roles and metadata.get(roles["npm"]):
                package, install_hooks = _parse_npm_manifest(metadata[roles["npm"]])
            if package is None and "pypi" in roles and metadata.get(roles["pypi"]):
                package = _parse_pypi_metadata(metadata[roles["pypi"]])

            archive_type = backend.archive_type
            if "wheel" in roles:
                archive_type = "wheel"
            elif package and package["ecosystem"] == "npm":
                archive_type = "npm"
            elif package and package["ecosystem"] == "PyPI":
                archive_type = "sdist"

            # ── Choose members ──
            hook_scripts = {_base(m).lower() for hook in install_hooks for m in _HOOK_SCRIPT_RE.findall(hook)}
            selected = self._select(entries, hook_scripts, notes)

            # ── Analyse ──
            contents = self._read(backend, {entry.name for entry in selected}, MAX_MEMBER_BYTES)
            analyzed = self._analyze_selected(selected, contents, notes)
        finally:
            backend.close()

        return {
            "archive_type": archive_type,
            "member_count": len(entries),
            "total_uncompressed_bytes": sum(max(entry.size, 0) for entry in entries),
            "package": package,
            "install_hooks": install_hooks,
            "analyzed_members": analyzed,
            "notes": notes[:MAX_NOTES],
            "imports": _unique([i for m in analyzed for i in m["imports"]], MAX_AGGREGATE_ITEMS),
            "suspicious_calls": _unique([c for m in analyzed for c in m["suspicious_calls"]], MAX_AGGREGATE_ITEMS),
            "high_value_strings": _unique([s for m in analyzed for s in m["high_value_strings"]], MAX_AGGREGATE_ITEMS),
        }

    @staticmethod
    def _read(backend: Any, names: Set[str], limit: int) -> Dict[str, Optional[bytes]]:
        """Read the named members; oversized or unreadable ones map to None."""
        contents: Dict[str, Optional[bytes]] = {}
        if not names:
            return contents
        try:
            for name, data in backend.read(names, limit):
                contents[name] = data if data is not None and len(data) <= limit else None
        except _READ_ERRORS as e:
            logger.warning(f"[Archive] stopped reading members: {e}")
        return contents

    @staticmethod
    def _select(entries: List[_Entry], hook_scripts: Set[str], notes: List[str]) -> List[_Entry]:
        """Pick the members to analyse, most install-relevant first."""
        for entry in entries:
            if _is_traversal(entry.name):
                notes.append(f"path traversal attempt in member name: {_display_path(entry.name)}")
            if _ext(entry.name) in NESTED_EXTENSIONS:
                notes.append(f"nested archive not unpacked: {_display_path(entry.name)}")

        ranked = sorted(
            (entry for entry in entries if _priority(entry, hook_scripts) > 0),
            key=lambda e: (-_priority(e, hook_scripts), _depth(e.name), e.name),
        )
        selected: List[_Entry] = []
        binaries = 0
        over_limit = 0
        for entry in ranked:
            is_binary = _ext(entry.name) in BINARY_EXTENSIONS
            if entry.size > MAX_MEMBER_BYTES:
                notes.append(f"skipped oversized member: {_display_path(entry.name)} ({entry.size} bytes)")
            elif len(selected) >= MAX_MEMBERS_ANALYZED or (is_binary and binaries >= MAX_BINARY_MEMBERS):
                over_limit += 1
            else:
                selected.append(entry)
                binaries += int(is_binary)
        if over_limit:
            notes.append(f"{over_limit} member(s) not analysed (limit of {MAX_MEMBERS_ANALYZED} members, "
                         f"{MAX_BINARY_MEMBERS} binaries)")
        return selected

    def _analyze_selected(self, selected: List[_Entry], contents: Dict[str, Optional[bytes]],
                          notes: List[str]) -> List[Dict[str, Any]]:
        analyzed: List[Dict[str, Any]] = []
        deadline = time.monotonic() + ANALYSIS_BUDGET_SECONDS
        out_of_time = 0
        for entry in selected:
            path = _display_path(entry.name)
            data = contents.get(entry.name)
            if data is None:
                notes.append(f"unreadable member (encrypted, corrupt or oversized): {path}")
                continue
            if time.monotonic() > deadline:
                out_of_time += 1
                continue
            record = self._analyze_one(path, data)
            if record is not None:
                analyzed.append(record)
        if out_of_time:
            notes.append(f"{out_of_time} member(s) not analysed (time budget of {ANALYSIS_BUDGET_SECONDS:g}s)")
        return analyzed

    def _analyze_one(self, path: str, data: bytes) -> Optional[Dict[str, Any]]:
        """Analyse one member from a randomly named temp file."""
        fd, temp_path = tempfile.mkstemp(prefix="origintrace_member_", suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            result = self._analyze_member(temp_path, _base(path) or "member")
        except Exception as e:
            logger.warning(f"[Archive] member analysis failed for {path}: {e}")
            return None
        finally:
            try:
                os.remove(temp_path)
            except OSError as e:
                logger.warning(f"[Archive] could not remove temp file {temp_path}: {e}")

        features = result.get("features")
        if not isinstance(features, dict):
            return None
        return _member_record(path, data, str(result.get("file_type") or "unknown"), features)
