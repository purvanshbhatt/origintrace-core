"""
OriginTrace — Document / Macro Extractor

Handles weaponized Microsoft Office documents (DOC, DOCM, XLS, XLSM, PPTM).
Uses oletools.olevba to extract hidden VBA macro source code, then scans for
AutoOpen triggers, Shell/CreateObject calls, PowerShell invocations, and
embedded URLs.
"""
import re
import logging
from typing import Dict, Any, List

from extractors.ioc import URL_RE

logger = logging.getLogger("origintrace.macro_extractor")

MAX_MACRO_SOURCE_CHARS = 4000   # truncate for the LLM context window

# VBA keywords that indicate malicious intent
SUSPICIOUS_VBA_KEYWORDS = [
    re.compile(r'\bAutoOpen\b', re.IGNORECASE),
    re.compile(r'\bAuto_Open\b', re.IGNORECASE),
    re.compile(r'\bAutoExec\b', re.IGNORECASE),
    re.compile(r'\bAutoClose\b', re.IGNORECASE),
    re.compile(r'\bDocument_Open\b', re.IGNORECASE),
    re.compile(r'\bDocument_Close\b', re.IGNORECASE),
    re.compile(r'\bWorkbook_Open\b', re.IGNORECASE),
    re.compile(r'\bShell\b', re.IGNORECASE),
    re.compile(r'\bCreateObject\b', re.IGNORECASE),
    re.compile(r'\bWScript\.Shell\b', re.IGNORECASE),
    re.compile(r'\bPowerShell\b', re.IGNORECASE),
    re.compile(r'\bCmd\.exe\b', re.IGNORECASE),
    re.compile(r'\bURLDownloadToFile\b', re.IGNORECASE),
    re.compile(r'\bCallByName\b', re.IGNORECASE),
    re.compile(r'\bGetObject\b', re.IGNORECASE),
    re.compile(r'\bEnviron\b', re.IGNORECASE),
    re.compile(r'\bChrW?\s*\(', re.IGNORECASE),  # Character code obfuscation
]

_OLE_NATIVE_STREAM = "\x01ole10native"


def scan_macro_source(source: str) -> Dict[str, List[str]]:
    """Scan VBA source for suspicious keywords and embedded URLs."""
    keywords: List[str] = []
    seen = set()
    for pattern in SUSPICIOUS_VBA_KEYWORDS:
        for match in pattern.finditer(source):
            kw = match.group(0).strip()
            if kw and kw.lower() not in seen:
                seen.add(kw.lower())
                keywords.append(kw)

    urls = list(dict.fromkeys(match.group(0).rstrip(".,;:") for match in URL_RE.finditer(source)))
    return {"suspicious_keywords": keywords, "embedded_urls": urls}


def _embedded_ole_objects(file_path: str) -> List[str]:
    """List OLE objects embedded in a document (droppers hide payloads here)."""
    from oletools import oleobj

    objects: List[str] = []
    for ole in oleobj.find_ole(file_path, None):
        if ole is None:
            continue
        for stream_parts in ole.listdir():
            if stream_parts[-1].lower() != _OLE_NATIVE_STREAM:
                continue
            label = "<embedded>"
            try:
                native = oleobj.OleNativeStream(ole.openstream(stream_parts))
                label = native.filename or native.src_path or label
            except Exception as e:
                logger.debug(f"[MacroExtractor] Unparseable Ole10Native stream: {e}")
            objects.append(f"OLE Object #{len(objects)}: {label}")
    return objects


class MacroExtractor:
    """Extraction pipeline for Office documents with embedded VBA macros."""

    def extract(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Analyze an Office document for malicious macros.
        Returns a dict compatible with DocumentFeatures schema.
        """
        result = {
            "doc_type": "unknown",
            "has_macros": False,
            "macro_source": None,
            "suspicious_keywords": [],
            "embedded_urls": [],
            "embedded_ole_objects": [],
            "high_value_strings": [],
        }

        try:
            from oletools.olevba import VBA_Parser
        except ImportError:
            logger.warning("[MacroExtractor] oletools not installed; macro analysis skipped")
            return result

        vba_parser = None
        try:
            vba_parser = VBA_Parser(file_path)
            result["doc_type"] = vba_parser.type or "unknown"

            if vba_parser.detect_vba_macros():
                result["has_macros"] = True

                # Extract all VBA macro source code
                all_macro_code = []
                for (_container, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    if vba_code:
                        all_macro_code.append(
                            f"// --- Module: {vba_filename} (Stream: {stream_path}) ---\n{vba_code}"
                        )

                full_source = "\n\n".join(all_macro_code)
                # Scan the full source, but only forward a truncated copy.
                scan = scan_macro_source(full_source)
                result["suspicious_keywords"] = scan["suspicious_keywords"]
                result["embedded_urls"] = scan["embedded_urls"]
                result["high_value_strings"].extend(scan["embedded_urls"])

                if len(full_source) > MAX_MACRO_SOURCE_CHARS:
                    full_source = full_source[:MAX_MACRO_SOURCE_CHARS] + "\n' [TRUNCATED]"
                result["macro_source"] = full_source

                # ── oletools analysis results (IOCs, suspicious patterns) ──
                try:
                    for (kw_type, keyword, _description) in vba_parser.analyze_macros():
                        entry = f"{kw_type}: {keyword}"
                        if entry not in result["high_value_strings"]:
                            result["high_value_strings"].append(entry)
                except Exception as e:
                    logger.debug(f"[MacroExtractor] analyze_macros failed: {e}")

        except Exception as e:
            logger.warning(f"[MacroExtractor] oletools failed: {e}")
        finally:
            if vba_parser is not None:
                try:
                    vba_parser.close()
                except Exception:
                    pass

        # ── OLE embedded objects ──
        try:
            result["embedded_ole_objects"] = _embedded_ole_objects(file_path)
        except Exception as e:
            # Not all documents have embedded OLE objects
            logger.debug(f"[MacroExtractor] OLE object scan skipped: {e}")

        return result
