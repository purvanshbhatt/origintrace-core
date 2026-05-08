"""
OriginTrace — ELF Binary Extractor

Parses Linux ELF executables and shared objects using pyelftools for header
inspection and r2ghidra for deep decompilation. Outputs a BinaryFeatures
schema with ELF-specific fields (elf_type, elf_machine, elf_symbols).
"""
import hashlib
import re
import logging
import r2pipe
from typing import Dict, Any, List

logger = logging.getLogger("origintrace.elf_extractor")


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

            with open(file_path, "rb") as f:
                elf = ELFFile(f)

                result["elf_type"] = elf.header["e_type"]
                result["elf_machine"] = elf.header["e_machine"]

                # Section entropy approximation
                for section in elf.iter_sections():
                    name = section.name or "<unnamed>"
                    size = section["sh_size"]
                    result["sections"].append(f"{name} (Size: {size})")

                # Dynamic symbol table (equivalent to IAT for ELF)
                from elftools.elf.sections import SymbolTableSection
                for section in elf.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for sym in section.iter_symbols():
                            if sym.name and sym["st_shndx"] == "SHN_UNDEF":
                                # Undefined = external dependency (like an import)
                                result["imports"].append(sym.name)
                                result["elf_symbols"].append(sym.name)
                            elif sym.name:
                                result["elf_symbols"].append(f"LOCAL:{sym.name}")

        except Exception as e:
            logger.warning(f"[ELFExtractor] pyelftools failed: {e}")

        # ── r2ghidra: Deep Decompilation ──
        try:
            r2 = r2pipe.open(file_path)

            # Verify it's a real binary
            info = r2.cmdj("iIj")
            if info and info.get("bintype", "any") == "any":
                r2.quit()
                return result

            r2.cmd("aa")

            # IOC-grade string filtering
            strings_json = r2.cmdj("izj")
            if strings_json:
                ioc_patterns = [
                    re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'),
                    re.compile(r'https?://[^\s]+'),
                    re.compile(r'/etc/|/tmp/|/dev/|/proc/'),
                    re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
                ]
                for s in strings_json:
                    string_val = s.get("string", "")
                    if any(p.search(string_val) for p in ioc_patterns):
                        result["high_value_strings"].append(string_val)

            # Decompile entry point
            r2.cmd("s entry0")
            try:
                decomp = r2.cmdj("pdgj")
                if decomp and isinstance(decomp, dict) and "code" in decomp:
                    code = decomp["code"]
                    if len(code) > 2000:
                        code = code[:2000] + "\n// [TRUNCATED]"
                    result["functions"].append({
                        "name": "entry0",
                        "decompiled_c": code,
                        "symbolic_resolved_strings": []
                    })
            except Exception:
                pass

            r2.quit()
        except Exception as e:
            logger.warning(f"[ELFExtractor] r2pipe failed: {e}")

        return result
