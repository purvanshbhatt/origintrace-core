"""
OriginTrace — ELF Binary Extractor

Parses Linux ELF executables and shared objects using pyelftools for header
inspection and r2ghidra for deep decompilation. Outputs a BinaryFeatures
schema with ELF-specific fields (elf_type, elf_machine, elf_symbols).
"""
import re
import logging
from typing import Dict, Any

from extractors.ioc import is_ioc, scan_file_for_iocs
from extractors.r2util import open_r2

logger = logging.getLogger("origintrace.elf_extractor")

MAX_SYMBOLS = 300          # keep the SSE payload and LLM context bounded
MAX_DECOMPILED_CHARS = 2000
_ELF_PATH_RE = re.compile(r'/etc/|/tmp/|/dev/|/proc/')


class ELFExtractor:
    """Extraction pipeline for Linux ELF binaries."""

    def extract(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Full ELF extraction: headers via pyelftools, strings + decompilation via r2ghidra.
        Returns a dict compatible with BinaryFeatures schema.
        """
        result = {
            "imports": [],
            "sections": [],
            "functions": [],
            "high_value_strings": [],
            "elf_type": None,
            "elf_machine": None,
            "elf_symbols": [],
        }

        # ── pyelftools: Header + Symbol Table ──
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.sections import SymbolTableSection

            with open(file_path, "rb") as f:
                elf = ELFFile(f)

                result["elf_type"] = elf.header["e_type"]
                result["elf_machine"] = elf.header["e_machine"]

                imports: Dict[str, None] = {}
                symbols: Dict[str, None] = {}
                for section in elf.iter_sections():
                    name = section.name or "<unnamed>"
                    size = section["sh_size"]
                    result["sections"].append(f"{name} (Size: {size})")

                    # Symbol tables (.dynsym is the ELF equivalent of the IAT)
                    if isinstance(section, SymbolTableSection):
                        for sym in section.iter_symbols():
                            if not sym.name:
                                continue
                            if sym["st_shndx"] == "SHN_UNDEF":
                                # Undefined = external dependency (like an import)
                                imports[sym.name] = None
                                symbols[sym.name] = None
                            else:
                                symbols[f"LOCAL:{sym.name}"] = None

                result["imports"] = list(imports)
                result["elf_symbols"] = list(symbols)[:MAX_SYMBOLS]

        except Exception as e:
            logger.warning(f"[ELFExtractor] pyelftools failed: {e}")

        # ── r2ghidra: Deep Decompilation ──
        try:
            self._extract_with_r2(file_path, result)
        except Exception as e:
            logger.warning(f"[ELFExtractor] r2pipe failed: {e}")

        # ── Fallback: pure-Python string scan when r2 gave us nothing ──
        if not result["high_value_strings"]:
            try:
                result["high_value_strings"] = scan_file_for_iocs(file_path)
            except OSError as e:
                logger.warning(f"[ELFExtractor] string scan failed: {e}")

        return result

    def _extract_with_r2(self, file_path: str, result: Dict[str, Any]) -> None:
        """Populate strings and the decompiled entry point via radare2."""
        r2 = open_r2(file_path)
        if r2 is None:
            return

        try:
            # Verify it's a real binary
            info = r2.cmdj("iIj")
            if info and info.get("bintype", "any") == "any":
                return

            r2.cmd("aa")

            # IOC-grade string filtering
            strings_json = r2.cmdj("izj")
            if strings_json:
                for s in strings_json:
                    string_val = s.get("string", "")
                    if is_ioc(string_val) or _ELF_PATH_RE.search(string_val):
                        result["high_value_strings"].append(string_val)

            # Decompile entry point
            r2.cmd("s entry0")
            try:
                decomp = r2.cmdj("pdgj")
                if decomp and isinstance(decomp, dict) and "code" in decomp:
                    code = decomp["code"]
                    if len(code) > MAX_DECOMPILED_CHARS:
                        code = code[:MAX_DECOMPILED_CHARS] + "\n// [TRUNCATED]"
                    result["functions"].append({
                        "name": "entry0",
                        "decompiled_c": code,
                        "symbolic_resolved_strings": []
                    })
            except Exception as e:
                logger.debug(f"[ELFExtractor] entry decompilation failed: {e}")
        finally:
            r2.quit()
