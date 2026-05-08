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

logger = logging.getLogger("origintrace.macro_extractor")

# VBA keywords that indicate malicious intent
SUSPICIOUS_VBA_KEYWORDS = [
    re.compile(r'\bAutoOpen\b', re.IGNORECASE),
    re.compile(r'\bAuto_Open\b', re.IGNORECASE),
    re.compile(r'\bDocument_Open\b', re.IGNORECASE),
    re.compile(r'\bWorkbook_Open\b', re.IGNORECASE),
    re.compile(r'\bShell\b', re.IGNORECASE),
    re.compile(r'\bCreateObject\b', re.IGNORECASE),
    re.compile(r'\bWScript\.Shell\b', re.IGNORECASE),
    re.compile(r'\bPowerShell\b', re.IGNORECASE),
    re.compile(r'\bCmd\.exe\b', re.IGNORECASE),
    re.compile(r'\bURLDownloadToFile\b', re.IGNORECASE),
    re.compile(r'\bMsgBox\b', re.IGNORECASE),
    re.compile(r'\bCallByName\b', re.IGNORECASE),
    re.compile(r'\bGetObject\b', re.IGNORECASE),
    re.compile(r'\bEnviron\b', re.IGNORECASE),
    re.compile(r'\bChrW?\s*\(', re.IGNORECASE),  # Character code obfuscation
]

URL_PATTERN = re.compile(r'https?://[^\s"\'`\\>]+')


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

            vba_parser = VBA_Parser(file_path)
            result["doc_type"] = vba_parser.type or "unknown"

            if vba_parser.detect_vba_macros():
                result["has_macros"] = True

                # Extract all VBA macro source code
                all_macro_code = []
                for (filename_vba, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    if vba_code:
                        all_macro_code.append(
                            f"// --- Module: {vba_filename} (Stream: {stream_path}) ---\n{vba_code}"
                        )

                combined_source = "\n\n".join(all_macro_code)
                # Truncate for LLM context window
                if len(combined_source) > 4000:
                    combined_source = combined_source[:4000] + "\n' [TRUNCATED]"
                result["macro_source"] = combined_source

                # ── Suspicious keyword scan ──
                for pattern in SUSPICIOUS_VBA_KEYWORDS:
                    matches = pattern.findall(combined_source)
                    for match in matches:
                        kw = match.strip()
                        if kw and kw not in result["suspicious_keywords"]:
                            result["suspicious_keywords"].append(kw)

                # ── URL extraction from macro code ──
                for match in URL_PATTERN.finditer(combined_source):
                    url = match.group()
                    if url not in result["embedded_urls"]:
                        result["embedded_urls"].append(url)
                        result["high_value_strings"].append(url)

                # ── oletools analysis results (IOCs, suspicious patterns) ──
                try:
                    analysis = vba_parser.analyze_macros()
                    for (kw_type, keyword, description) in analysis:
                        entry = f"{kw_type}: {keyword}"
                        if entry not in result["high_value_strings"]:
                            result["high_value_strings"].append(entry)
                except Exception:
                    pass

            # ── OLE embedded objects ──
            try:
                from oletools import oleobj
                for index, ole_obj in enumerate(oleobj.find_ole(file_path)):
                    if hasattr(ole_obj, "filename"):
                        result["embedded_ole_objects"].append(
                            f"OLE Object #{index}: {ole_obj.filename}"
                        )
                    else:
                        result["embedded_ole_objects"].append(f"OLE Object #{index}: <embedded>")
            except Exception:
                pass  # Not all documents have embedded OLE objects

            vba_parser.close()

        except Exception as e:
            logger.warning(f"[MacroExtractor] oletools failed: {e}")

        return result
