"""
OriginTrace — Universal File Type Router

Autonomous MIME-based routing gateway that inspects magic bytes to determine
file type, then dispatches to the appropriate specialized extractor:

  PE (x-dosexec)     → PEExtractor + ConcolicEngine + r2ghidra
  ELF (x-executable) → ELFExtractor + r2ghidra
  Script (text/*)     → ScriptExtractor (AST + regex + entropy)
  Document (ms-office)→ MacroExtractor (oletools VBA extraction)

All extractors produce a normalized dict that maps to the ExtractionResult
Pydantic schema before being passed to the LLM Intelligence Agent.
"""
import hashlib
import os
import re
import logging
import pefile
import r2pipe
from typing import Dict, Any, List

from extractors.elf_extractor import ELFExtractor
from extractors.script_extractor import ScriptExtractor
from extractors.macro_extractor import MacroExtractor

# Lazy imports for heavy dependencies (angr, faiss, sentence-transformers)
# These are only loaded when actually needed in production
_provenance_engine_cls = None
_resolve_with_timeout = None

def _get_provenance_engine():
    global _provenance_engine_cls
    if _provenance_engine_cls is None:
        from extractors.provenance import ProvenanceEngine
        _provenance_engine_cls = ProvenanceEngine
    return _provenance_engine_cls()

def _get_resolve_with_timeout():
    global _resolve_with_timeout
    if _resolve_with_timeout is None:
        from extractors.symbolic_resolver import resolve_with_timeout
        _resolve_with_timeout = resolve_with_timeout
    return _resolve_with_timeout

logger = logging.getLogger("origintrace.extractor")

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

# Extension-based fallback for when libmagic isn't available or returns text/plain
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


def _detect_file_type(file_path: str, filename: str) -> str:
    """
    Detect file type using python-magic (libmagic), with extension fallback.
    Returns one of: 'pe', 'elf', 'script', 'document', 'unknown'.
    """
    mime_type = None

    # Strategy 1: python-magic MIME detection
    try:
        import magic
        mime_type = magic.from_file(file_path, mime=True)
        logger.info(f"[Router] Detected MIME: {mime_type} for {filename}")

        if mime_type in MIME_ROUTING_TABLE:
            return MIME_ROUTING_TABLE[mime_type]

        # Handle generic text/plain — fall through to extension check
        if mime_type and mime_type.startswith("text/"):
            # Could be a script with a generic MIME
            pass

    except ImportError:
        logger.warning("[Router] python-magic not installed, falling back to extension detection")
    except Exception as e:
        logger.warning(f"[Router] magic detection failed: {e}")

    # Strategy 2: Extension-based fallback
    ext = os.path.splitext(filename)[1].lower()
    if ext in EXTENSION_FALLBACK:
        logger.info(f"[Router] Extension fallback: {ext} → {EXTENSION_FALLBACK[ext]}")
        return EXTENSION_FALLBACK[ext]

    # Strategy 3: Magic bytes header check (last resort)
    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
        if header[:2] == b'MZ':
            return "pe"
        if header[:4] == b'\x7fELF':
            return "elf"
        if header[:2] == b'#!':
            return "script"
        # OLE Compound Document (legacy Office)
        if header[:4] == b'\xd0\xcf\x11\xe0':
            return "document"
        # OOXML (ZIP-based Office)
        if header[:4] == b'PK\x03\x04':
            return "document"
    except Exception:
        pass

    return "unknown"


def _compute_hashes(file_path: str) -> Dict[str, Any]:
    """Compute SHA256, MD5 and file size."""
    result = {"sha256": None, "md5": None, "size": None}
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            result["sha256"] = hashlib.sha256(data).hexdigest()
            result["md5"] = hashlib.md5(data).hexdigest()
            result["size"] = len(data)
    except Exception as e:
        logger.warning(f"[Hashes] Failed: {e}")
    return result


class MasterBinaryExtractor:
    """
    Universal file type router. Determines the input format via magic bytes,
    dispatches to the appropriate specialized extractor, and normalizes
    the output into a unified schema for the LLM pipeline.
    """

    def __init__(self):
        self.provenance_engine = _get_provenance_engine()
        self.elf_extractor = ELFExtractor()
        self.script_extractor = ScriptExtractor()
        self.macro_extractor = MacroExtractor()

    def extract_all(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Unified extraction entry point. Routes to the correct extractor
        based on detected file type, then runs provenance analysis.
        """
        # ── Step 0: Detect file type ──
        file_type = _detect_file_type(file_path, filename)
        logger.info(f"[Router] File '{filename}' classified as: {file_type}")

        # ── Step 1: Compute universal metadata ──
        hashes = _compute_hashes(file_path)
        result = {
            "metadata": {
                "filename": filename,
                "sha256": hashes["sha256"],
                "md5": hashes["md5"],
                "size": hashes["size"],
                "file_type": file_type,
            },
            "file_type": file_type,
            "binary_features": None,
            "script_features": None,
            "document_features": None,
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

            else:
                # Unknown file type — attempt basic string extraction
                result["status"] = "warning: unknown file type, limited analysis performed"
                result["script_features"] = self._extract_unknown(file_path, filename)
                all_strings = result["script_features"].get("high_value_strings", [])

        except Exception as e:
            result["status"] = f"error: extraction failed - {str(e)}"
            logger.error(f"[Router] Extraction failed for {filename}: {e}")

        # ── Step 3: Semantic Provenance Engine (universal) ──
        try:
            provenance_data = self.provenance_engine.analyze_delta(all_strings, all_imports)
            result["provenance"] = provenance_data
        except Exception as e:
            result["status"] = f"{result['status']} | Warning: Provenance Engine failed - {str(e)}"

        return result

    # ── PE Extraction (existing pipeline) ──────────────────────

    def _extract_pe(self, file_path: str, filename: str) -> Dict[str, Any]:
        """Full PE extraction: pefile + r2ghidra + concolic execution."""
        features = {
            "imports": [],
            "sections": [],
            "functions": [],
            "high_value_strings": [],
            "imphash": None,
        }

        all_strings = []
        concolic_targets: List[Dict[str, Any]] = []

        # ── pefile: Shallow PE Parsing ──
        try:
            pe = pefile.PE(file_path)

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

        except Exception as e:
            logger.warning(f"[PEExtractor] pefile failed: {e}")

        # ── r2ghidra: Deep Decompilation ──
        try:
            r2 = r2pipe.open(file_path)

            info = r2.cmdj("iIj")
            if info and info.get("bintype", "any") == "any":
                r2.quit()
                return features

            r2.cmd("aa")

            # IOC string filtering
            strings_json = r2.cmdj("izj")
            if strings_json:
                ioc_patterns = [
                    re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'),
                    re.compile(r'https?://[^\s]+'),
                    re.compile(r'[A-Za-z]:\\[^\s]+'),
                    re.compile(r'HK[LC]U\\[^\s]+'),
                    re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
                ]
                for s in strings_json:
                    string_val = s.get("string", "")
                    if any(pattern.search(string_val) for pattern in ioc_patterns):
                        all_strings.append(string_val)
                        features["high_value_strings"].append(string_val)

            # Exported functions
            exports_json = r2.cmdj("iEj")
            if exports_json:
                for exp in exports_json:
                    if "name" in exp:
                        all_strings.append(f"EXPORT:{exp['name']}")

            # Decompile entry point
            r2.cmd("s entry0")
            entry_addr = r2.cmdj("sj") or 0
            try:
                disasm_json = r2.cmdj("pdgj")
                if disasm_json and isinstance(disasm_json, dict) and "code" in disasm_json:
                    code = disasm_json["code"]
                    if len(code) > 2000:
                        code = code[:2000] + "\n// [TRUNCATED]"

                    features["functions"].append({
                        "name": "entry0",
                        "decompiled_c": code,
                        "symbolic_resolved_strings": []
                    })

                    if _has_obfuscation_markers(code):
                        concolic_targets.append({
                            "func_index": len(features["functions"]) - 1,
                            "start_addr": entry_addr if isinstance(entry_addr, int) else 0
                        })
            except Exception:
                pass

            # Targeted decompilation for suspicious API callers
            suspicious_apis = ["VirtualAlloc", "CryptEncrypt", "InternetOpen",
                               "CreateProcess", "GetProcAddress", "LoadLibrary"]
            imports_json = r2.cmdj("iij")
            if imports_json:
                for imp in imports_json:
                    imp_name = imp.get("name", "")
                    if any(sus_api.lower() in imp_name.lower() for sus_api in suspicious_apis):
                        xrefs = r2.cmdj(f"axtj sym.imp.{imp_name}")
                        if not xrefs:
                            xrefs = r2.cmdj(f"axtj {imp_name}")
                        if xrefs:
                            for xref in xrefs[:3]:
                                call_addr = xref.get("from", 0)
                                if call_addr:
                                    try:
                                        r2.cmd(f"s {call_addr}")
                                        func_decomp = r2.cmdj("pdgj")
                                        if func_decomp and isinstance(func_decomp, dict) and "code" in func_decomp:
                                            code = func_decomp["code"]
                                            if len(code) > 2000:
                                                code = code[:2000] + "\n// [TRUNCATED]"

                                            features["functions"].append({
                                                "name": f"func_{imp_name}_0x{call_addr:08x}",
                                                "decompiled_c": code,
                                                "symbolic_resolved_strings": []
                                            })

                                            if _has_obfuscation_markers(code):
                                                concolic_targets.append({
                                                    "func_index": len(features["functions"]) - 1,
                                                    "start_addr": call_addr
                                                })
                                    except Exception:
                                        pass

            r2.quit()
        except Exception as e:
            logger.warning(f"[PEExtractor] r2pipe failed: {e}")

        # ── Concolic Execution ──
        if concolic_targets:
            try:
                for target in concolic_targets:
                    resolve_fn = _get_resolve_with_timeout()
                    resolved = resolve_fn(
                        binary_path=file_path,
                        start_addr=target["start_addr"],
                        timeout=15
                    )
                    if resolved:
                        idx = target["func_index"]
                        features["functions"][idx]["symbolic_resolved_strings"] = resolved
                        all_strings.extend(resolved)
                        features["high_value_strings"].extend(resolved)
                        logger.info(f"[Concolic] Resolved {len(resolved)} strings at 0x{target['start_addr']:08x}")
            except Exception as e:
                logger.warning(f"[PEExtractor] Concolic engine failed: {e}")

        return features

    # ── Unknown File Fallback ──────────────────────────────────

    def _extract_unknown(self, file_path: str, filename: str) -> Dict[str, Any]:
        """Best-effort extraction for unrecognized file types."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read(5000)
        except Exception:
            source = ""

        return {
            "language": "unknown",
            "raw_source": source[:3000],
            "ast_imports": [],
            "suspicious_calls": [],
            "encoded_blobs": [],
            "obfuscation_score": 0.0,
            "high_value_strings": [],
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
