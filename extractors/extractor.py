"""
OriginTrace — Universal File Type Router

Autonomous routing gateway that inspects magic bytes to determine file type,
then dispatches to the appropriate specialized extractor:

  PE (MZ)             → pefile + r2ghidra + ConcolicEngine
  ELF (\\x7fELF)       → ELFExtractor + r2ghidra
  Script / plain text → ScriptExtractor (AST + regex + entropy)
  Office document     → MacroExtractor (oletools VBA extraction)
  Package / archive   → ArchiveExtractor (wheel, sdist, npm tarball, zip, tar)

All extractors produce a normalized dict that maps to the ExtractionResult
Pydantic schema before being passed to the analysis agents.

Heavy or system-level tooling (radare2, angr, libmagic, FAISS) is optional:
when a tool is missing the router degrades to pure-Python analysis instead
of failing. `get_capabilities()` reports what is available.
"""
import functools
import hashlib
import importlib.util
import os
import re
import logging
import threading
import zipfile
from typing import Dict, Any, List, Optional

from extractors.archive_extractor import ArchiveExtractor
from extractors.elf_extractor import ELFExtractor
from extractors.ioc import is_ioc, scan_file_for_iocs
from extractors.r2util import current_seek, open_r2, r2_available
from extractors.script_extractor import ScriptExtractor
from extractors.macro_extractor import MacroExtractor

# Lazy imports for heavy dependencies (angr, faiss, sentence-transformers)
# These are only loaded when actually needed in production
_resolve_with_timeout = None

def _get_resolve_with_timeout():
    global _resolve_with_timeout
    if _resolve_with_timeout is None:
        from extractors.symbolic_resolver import resolve_with_timeout
        _resolve_with_timeout = resolve_with_timeout
    return _resolve_with_timeout

logger = logging.getLogger("origintrace.extractor")

MAX_DECOMPILED_CHARS = 2000
MAX_DECOMPILED_FUNCTIONS = 8    # bound r2ghidra work and LLM context
MAX_XREFS_PER_API = 3
MAX_CONCOLIC_TARGETS = 3        # each target may cost a full concolic timeout
CONCOLIC_TIMEOUT_SECONDS = 15
HASH_CHUNK_BYTES = 1024 * 1024
TEXT_SNIFF_BYTES = 8192

SUSPICIOUS_APIS = ["VirtualAlloc", "CryptEncrypt", "InternetOpen",
                   "CreateProcess", "GetProcAddress", "LoadLibrary"]

# Regex patterns for detecting obfuscation candidates in decompiled C
OBFUSCATION_PATTERNS = [
    re.compile(r'\^'),           # XOR operations
    re.compile(r'<<|>>'),        # Bitwise shifts
    re.compile(r'GetProcAddress', re.IGNORECASE),
    re.compile(r'LoadLibrary', re.IGNORECASE),
    re.compile(r'call\s+[re][a-z]+', re.IGNORECASE),  # Indirect register calls
]

# MIME type → file class mapping
MIME_ROUTING_TABLE = {
    # Windows PE
    "application/x-dosexec": "pe",
    "application/x-msdos-program": "pe",
    "application/vnd.microsoft.portable-executable": "pe",
    # Linux ELF
    "application/x-executable": "elf",
    "application/x-sharedlib": "elf",
    "application/x-pie-executable": "elf",
    "application/x-elf": "elf",
    # Scripts
    "text/x-python": "script",
    "text/x-script.python": "script",
    "application/x-python-code": "script",
    "text/javascript": "script",
    "application/javascript": "script",
    "application/x-javascript": "script",
    "text/x-shellscript": "script",
    "application/x-sh": "script",
    "text/x-powershell": "script",
    # Office Documents
    "application/msword": "document",
    "application/vnd.ms-excel": "document",
    "application/vnd.ms-powerpoint": "document",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "document",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "document",
    "application/vnd.ms-excel.sheet.macroEnabled.12": "document",
    "application/vnd.ms-word.document.macroEnabled.12": "document",
}

# Extension-based fallback for when neither magic bytes nor libmagic decide
EXTENSION_FALLBACK = {
    ".exe": "pe", ".dll": "pe", ".sys": "pe", ".scr": "pe",
    ".elf": "elf", ".so": "elf", ".o": "elf",
    ".py": "script", ".pyw": "script",
    ".js": "script", ".mjs": "script", ".cjs": "script", ".ts": "script",
    ".sh": "script", ".bash": "script",
    ".ps1": "script", ".psm1": "script",
    ".bat": "script", ".cmd": "script",
    ".doc": "document", ".docm": "document", ".docx": "document",
    ".xls": "document", ".xlsm": "document", ".xlsx": "document",
    ".ppt": "document", ".pptm": "document", ".pptx": "document",
}

_OOXML_PREFIXES = ("word/", "xl/", "ppt/")
_TEXT_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")


def _is_ooxml(file_path: str) -> bool:
    """True when a ZIP container is an Office Open XML document."""
    try:
        with zipfile.ZipFile(file_path) as archive:
            names = archive.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    return "[Content_Types].xml" in names and any(n.startswith(_OOXML_PREFIXES) for n in names)


def _looks_like_text(head: bytes) -> bool:
    """Cheap text sniff: no NULs and almost entirely printable bytes."""
    if not head:
        return False
    if head.startswith(_TEXT_BOMS):
        return True
    if b"\x00" in head:
        return False
    printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b <= 126 or b >= 128)
    return printable / len(head) >= 0.95


def _classify_by_header(file_path: str, head: bytes) -> Optional[str]:
    """Classify from magic bytes, which a renamed file cannot fake."""
    if head[:2] == b'MZ':
        return "pe"
    if head[:4] == b'\x7fELF':
        return "elf"
    # OLE Compound Document (legacy Office)
    if head[:4] == b'\xd0\xcf\x11\xe0':
        return "document"
    # ZIP container: OOXML is an Office document, anything else is a package.
    if head[:2] == b'PK':
        if _is_ooxml(file_path):
            return "document"
        if zipfile.is_zipfile(file_path):
            return "archive"
    # gzip / bzip2 / xz streams and plain tarballs (npm, sdist)
    if head[:2] == b'\x1f\x8b' or head[:3] == b'BZh' or head[:6] == b'\xfd7zXZ\x00' or head[257:262] == b'ustar':
        return "archive"
    return None


@functools.lru_cache(maxsize=1)
def _load_magic() -> Optional[Any]:
    """Import python-magic once; None when the package or libmagic is missing."""
    try:
        import magic
        return magic
    except Exception as e:  # ImportError, or OSError when the C library is absent
        logger.info(f"[Router] libmagic unavailable ({type(e).__name__}); using header and extension detection")
        return None


def detect_file_type(file_path: str, filename: str) -> str:
    """
    Detect file type from magic bytes, then libmagic, extension, and content.
    Returns one of: 'pe', 'elf', 'script', 'document', 'archive', 'unknown'.
    """
    try:
        with open(file_path, "rb") as f:
            head = f.read(TEXT_SNIFF_BYTES)
    except OSError as e:
        logger.warning(f"[Router] Could not read {filename}: {e}")
        head = b""

    # Strategy 1: Magic bytes — authoritative for binaries and Office files
    by_header = _classify_by_header(file_path, head)
    if by_header:
        return by_header

    # Strategy 2: python-magic MIME detection
    magic = _load_magic()
    if magic is not None:
        try:
            mime_type = magic.from_file(file_path, mime=True)
            logger.info(f"[Router] Detected MIME: {mime_type} for {filename}")
            if mime_type in MIME_ROUTING_TABLE:
                return MIME_ROUTING_TABLE[mime_type]
        except Exception as e:
            logger.warning(f"[Router] magic detection failed: {e}")

    # Strategy 3: Extension-based fallback
    ext = os.path.splitext(filename)[1].lower()
    if ext in EXTENSION_FALLBACK:
        logger.info(f"[Router] Extension fallback: {ext} → {EXTENSION_FALLBACK[ext]}")
        return EXTENSION_FALLBACK[ext]

    # Strategy 4: Plain text of any kind gets the script scanner
    if _looks_like_text(head):
        return "script"

    return "unknown"


def _compute_hashes(file_path: str) -> Dict[str, Any]:
    """Compute SHA256, MD5 and file size without loading the file into memory."""
    result = {"sha256": None, "md5": None, "size": None}
    try:
        sha256, md5, size = hashlib.sha256(), hashlib.md5(), 0
        with open(file_path, "rb") as f:
            while chunk := f.read(HASH_CHUNK_BYTES):
                sha256.update(chunk)
                md5.update(chunk)
                size += len(chunk)
        result = {"sha256": sha256.hexdigest(), "md5": md5.hexdigest(), "size": size}
    except OSError as e:
        logger.warning(f"[Hashes] Failed: {e}")
    return result


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def get_capabilities() -> Dict[str, bool]:
    """Report which optional analysis tooling this process can use."""
    return {
        "radare2": r2_available(),
        "pefile": _module_available("pefile"),
        "pyelftools": _module_available("elftools"),
        "oletools": _module_available("oletools"),
        "libmagic": _load_magic() is not None,
        "angr": _module_available("angr"),
        "faiss_provenance": _module_available("faiss") and _module_available("sentence_transformers"),
    }


class MasterBinaryExtractor:
    """
    Universal file type router. Determines the input format via magic bytes,
    dispatches to the appropriate specialized extractor, and normalizes
    the output into a unified schema for the analysis pipeline.
    """

    def __init__(self, provenance_engine: Optional[Any] = None):
        # The provenance engine can take seconds to load (embedding model),
        # so it is built on first use rather than at startup.
        self._provenance_engine = provenance_engine
        self._provenance_ready = provenance_engine is not None
        self._provenance_lock = threading.Lock()
        self.elf_extractor = ELFExtractor()
        self.script_extractor = ScriptExtractor()
        self.macro_extractor = MacroExtractor()
        self.archive_extractor = ArchiveExtractor(self._analyze_member)

    @property
    def provenance_engine(self) -> Optional[Any]:
        """The provenance engine, created lazily (None when disabled)."""
        if not self._provenance_ready:
            with self._provenance_lock:
                if not self._provenance_ready:
                    from extractors.provenance import get_provenance_engine
                    self._provenance_engine = get_provenance_engine()
                    self._provenance_ready = True
        return self._provenance_engine

    def warm_up(self) -> None:
        """Load the provenance engine ahead of the first request."""
        try:
            _ = self.provenance_engine
        except Exception as e:
            logger.warning(f"[Router] Provenance warm-up failed: {e}")

    def extract_all(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Unified extraction entry point. Routes to the correct extractor
        based on detected file type, then runs provenance analysis.
        """
        # ── Step 0: Detect file type ──
        file_type = detect_file_type(file_path, filename)
        logger.info(f"[Router] File '{filename}' classified as: {file_type}")

        # A known extension that contradicts the content is itself a signal.
        claimed_type = EXTENSION_FALLBACK.get(os.path.splitext(filename)[1].lower())
        extension_mismatch = bool(claimed_type and file_type != "unknown" and claimed_type != file_type)

        # ── Step 1: Compute universal metadata ──
        hashes = _compute_hashes(file_path)
        result = {
            "metadata": {
                "filename": filename,
                "sha256": hashes["sha256"],
                "md5": hashes["md5"],
                "size": hashes["size"],
                "file_type": file_type,
                "extension_mismatch": extension_mismatch,
            },
            "file_type": file_type,
            "binary_features": None,
            "script_features": None,
            "document_features": None,
            "archive_features": None,
            "provenance": {
                "ecosystem_match": "None",
                "legitimate_baseline": [],
                "injected_artifacts": []
            },
            "status": "success"
        }

        all_imports = []
        all_strings = []

        # ── Step 2: Route to specialized extractor ──
        try:
            if file_type == "pe":
                features = self._extract_pe(file_path, filename)
                result["binary_features"] = features
                all_imports = features.get("imports", [])
                all_strings = features.get("high_value_strings", [])

            elif file_type == "elf":
                features = self.elf_extractor.extract(file_path, filename)
                result["binary_features"] = features
                all_imports = features.get("imports", [])
                all_strings = features.get("high_value_strings", [])

            elif file_type == "script":
                features = self.script_extractor.extract(file_path, filename)
                result["script_features"] = features
                all_imports = features.get("ast_imports", [])
                all_strings = features.get("high_value_strings", [])

            elif file_type == "document":
                features = self.macro_extractor.extract(file_path, filename)
                result["document_features"] = features
                all_strings = features.get("high_value_strings", [])

            elif file_type == "archive":
                features = self.archive_extractor.extract(file_path, filename)
                result["archive_features"] = features
                all_imports = features.get("imports", [])
                all_strings = features.get("high_value_strings", [])

            else:
                # Unknown binary format — fall back to raw string extraction
                result["status"] = "warning: unknown file type, limited analysis performed"
                result["binary_features"] = self._extract_unknown(file_path)
                all_strings = result["binary_features"]["high_value_strings"]

        except Exception as e:
            result["status"] = f"error: extraction failed - {str(e)}"
            logger.error(f"[Router] Extraction failed for {filename}: {e}")

        # ── Step 3: Semantic Provenance Engine (universal) ──
        try:
            engine = self.provenance_engine
            if engine is not None:
                result["provenance"] = engine.analyze_delta(all_strings, all_imports)
        except Exception as e:
            result["status"] = f"{result['status']} | Warning: Provenance Engine failed - {str(e)}"

        return result

    # ── Archive members ────────────────────────────────────────

    def _analyze_member(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Analyse one file extracted from an archive. Provenance is skipped (it
        runs once for the whole archive) and nested archives are not recursed.
        """
        file_type = detect_file_type(file_path, filename)
        features: Optional[Dict[str, Any]] = None
        if file_type == "pe":
            # Concolic execution is too slow to run per archive member.
            features = self._extract_pe(file_path, filename, concolic=False)
        elif file_type == "elf":
            features = self.elf_extractor.extract(file_path, filename)
        elif file_type == "script":
            features = self.script_extractor.extract(file_path, filename)
        elif file_type == "document":
            features = self.macro_extractor.extract(file_path, filename)
        return {"file_type": file_type, "features": features}

    # ── PE Extraction (existing pipeline) ──────────────────────

    def _extract_pe(self, file_path: str, filename: str, concolic: bool = True) -> Dict[str, Any]:
        """Full PE extraction: pefile + r2ghidra + concolic execution."""
        features = {
            "imports": [],
            "sections": [],
            "functions": [],
            "high_value_strings": [],
            "imphash": None,
        }

        concolic_targets: List[Dict[str, Any]] = []

        # ── pefile: Shallow PE Parsing ──
        try:
            import pefile

            pe = pefile.PE(file_path)
            try:
                features["imphash"] = pe.get_imphash()

                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "unknown.dll"
                        for imp in entry.imports:
                            if imp.name:
                                func = imp.name.decode("utf-8", errors="ignore")
                                import_str = f"{dll_name}:{func}"
                                features["imports"].append(import_str)

                for section in pe.sections:
                    sec_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                    entropy = section.get_entropy()
                    features["sections"].append(f"{sec_name} (Entropy: {entropy:.2f})")
            finally:
                pe.close()

        except Exception as e:
            logger.warning(f"[PEExtractor] pefile failed: {e}")

        # ── r2ghidra: Deep Decompilation ──
        try:
            self._extract_pe_with_r2(file_path, features, concolic_targets)
        except Exception as e:
            logger.warning(f"[PEExtractor] r2pipe failed: {e}")

        # ── Fallback: pure-Python string scan when r2 gave us nothing ──
        if not features["high_value_strings"]:
            try:
                features["high_value_strings"] = scan_file_for_iocs(file_path)
            except OSError as e:
                logger.warning(f"[PEExtractor] string scan failed: {e}")

        # ── Concolic Execution ──
        if concolic and concolic_targets:
            try:
                resolve_fn = _get_resolve_with_timeout()
                for target in concolic_targets[:MAX_CONCOLIC_TARGETS]:
                    resolved = resolve_fn(
                        binary_path=file_path,
                        start_addr=target["start_addr"],
                        timeout=CONCOLIC_TIMEOUT_SECONDS
                    )
                    if resolved:
                        idx = target["func_index"]
                        features["functions"][idx]["symbolic_resolved_strings"] = resolved
                        for value in resolved:
                            if value not in features["high_value_strings"]:
                                features["high_value_strings"].append(value)
                        logger.info(f"[Concolic] Resolved {len(resolved)} strings at 0x{target['start_addr']:08x}")
            except Exception as e:
                logger.warning(f"[PEExtractor] Concolic engine failed: {e}")

        return features

    def _extract_pe_with_r2(self, file_path: str, features: Dict[str, Any],
                            concolic_targets: List[Dict[str, Any]]) -> None:
        """Populate strings and decompiled functions via radare2 + r2ghidra."""
        r2 = open_r2(file_path)
        if r2 is None:
            return

        try:
            info = r2.cmdj("iIj")
            if info and info.get("bintype", "any") == "any":
                return

            r2.cmd("aa")

            # IOC string filtering
            strings_json = r2.cmdj("izj")
            if strings_json:
                for s in strings_json:
                    string_val = s.get("string", "")
                    if is_ioc(string_val):
                        features["high_value_strings"].append(string_val)

            # Decompile entry point
            r2.cmd("s entry0")
            self._decompile_at_seek(r2, "entry0", current_seek(r2), features, concolic_targets)

            # Targeted decompilation for suspicious API callers
            decompiled_addrs = set()
            imports_json = r2.cmdj("iij")
            if imports_json:
                for imp in imports_json:
                    imp_name = imp.get("name", "")
                    if not any(sus_api.lower() in imp_name.lower() for sus_api in SUSPICIOUS_APIS):
                        continue
                    xrefs = r2.cmdj(f"axtj sym.imp.{imp_name}")
                    if not xrefs:
                        xrefs = r2.cmdj(f"axtj {imp_name}")
                    for xref in (xrefs or [])[:MAX_XREFS_PER_API]:
                        if len(features["functions"]) >= MAX_DECOMPILED_FUNCTIONS:
                            return
                        call_addr = xref.get("from", 0)
                        # Decompile (and later emulate) from the start of the
                        # calling function, not from the call instruction.
                        fcn_addr = xref.get("fcn_addr") or call_addr
                        if not fcn_addr or fcn_addr in decompiled_addrs:
                            continue
                        decompiled_addrs.add(fcn_addr)
                        r2.cmd(f"s {fcn_addr}")
                        name = xref.get("fcn_name") or f"func_{imp_name}_0x{fcn_addr:08x}"
                        self._decompile_at_seek(r2, name, fcn_addr, features, concolic_targets,
                                                calls_api=imp_name)
        finally:
            r2.quit()

    @staticmethod
    def _decompile_at_seek(r2: Any, name: str, addr: int, features: Dict[str, Any],
                           concolic_targets: List[Dict[str, Any]],
                           calls_api: Optional[str] = None) -> None:
        """Decompile the function at radare2's current seek via r2ghidra."""
        try:
            decomp = r2.cmdj("pdgj")
        except Exception as e:
            logger.debug(f"[PEExtractor] decompilation of {name} failed: {e}")
            return
        if not (decomp and isinstance(decomp, dict) and "code" in decomp):
            return

        code = decomp["code"]
        if len(code) > MAX_DECOMPILED_CHARS:
            code = code[:MAX_DECOMPILED_CHARS] + "\n// [TRUNCATED]"

        record: Dict[str, Any] = {
            "name": name,
            "decompiled_c": code,
            "symbolic_resolved_strings": []
        }
        if calls_api:
            record["calls_api"] = calls_api
        features["functions"].append(record)

        if addr and _has_obfuscation_markers(code):
            concolic_targets.append({
                "func_index": len(features["functions"]) - 1,
                "start_addr": addr
            })

    # ── Unknown File Fallback ──────────────────────────────────

    def _extract_unknown(self, file_path: str) -> Dict[str, Any]:
        """Best-effort extraction for unrecognized binary formats."""
        try:
            strings = scan_file_for_iocs(file_path)
        except OSError as e:
            logger.warning(f"[Router] string scan failed: {e}")
            strings = []

        return {
            "imports": [],
            "sections": [],
            "functions": [],
            "high_value_strings": strings,
        }


def _has_obfuscation_markers(code: str) -> bool:
    """
    Heuristic: returns True if the decompiled C-pseudocode contains
    bitwise operations inside loops or dynamic API resolution patterns,
    indicating likely string encryption or API obfuscation.
    """
    has_loop = bool(re.search(r'\b(while|for|do)\b', code))
    has_bitwise = any(p.search(code) for p in OBFUSCATION_PATTERNS[:2])  # XOR, shifts
    has_dynamic_api = any(p.search(code) for p in OBFUSCATION_PATTERNS[2:4])  # GetProcAddress, LoadLibrary

    return (has_loop and has_bitwise) or has_dynamic_api
