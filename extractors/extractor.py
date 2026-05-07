import hashlib
import re
import logging
import pefile
import r2pipe
from typing import Dict, Any, List

from extractors.provenance import ProvenanceEngine
from extractors.symbolic_resolver import resolve_with_timeout

logger = logging.getLogger("origintrace.extractor")

# Regex patterns for detecting obfuscation candidates in decompiled C
OBFUSCATION_PATTERNS = [
    re.compile(r'\^'),           # XOR operations
    re.compile(r'<<|>>'),        # Bitwise shifts
    re.compile(r'GetProcAddress', re.IGNORECASE),
    re.compile(r'LoadLibrary', re.IGNORECASE),
    re.compile(r'call\s+[re][a-z]+', re.IGNORECASE),  # Indirect register calls
]


class MasterBinaryExtractor:
    def __init__(self):
        self.provenance_engine = ProvenanceEngine()

    def extract_all(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Unified extractor pipeline. Gracefully falls back on errors to provide maximum available data
        to the Intelligence Agent.
        """
        result = {
            "metadata": {
                "filename": filename,
                "sha256": None,
                "md5": None,
                "size": None
            },
            "static_features": {
                "imports": [],
                "sections": [],
                "functions": [],
                "high_value_strings": []
            },
            "provenance": {
                "ecosystem_match": "None",
                "legitimate_baseline": [],
                "injected_artifacts": []
            },
            "status": "success"
        }

        all_imports = []
        all_strings = []

        # Step A: Basic Crypto & File Metadata
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                result["metadata"]["sha256"] = hashlib.sha256(data).hexdigest()
                result["metadata"]["md5"] = hashlib.md5(data).hexdigest()
                result["metadata"]["size"] = len(data)
        except Exception as e:
            result["status"] = f"Warning: Basic crypto failed - {str(e)}"

        # Step B: Shallow PE Parsing (pefile)
        try:
            pe = pefile.PE(file_path)
            
            # Extract Import Address Table (IAT)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "unknown.dll"
                    for imp in entry.imports:
                        if imp.name:
                            func = imp.name.decode("utf-8", errors="ignore")
                            import_str = f"{dll_name}:{func}"
                            all_imports.append(import_str)
                            result["static_features"]["imports"].append(import_str)
            
            # Extract PE Sections and their Entropy
            for section in pe.sections:
                sec_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                entropy = section.get_entropy()
                result["static_features"]["sections"].append(f"{sec_name} (Entropy: {entropy:.2f})")
                
        except Exception as e:
            curr = result["status"]
            result["status"] = f"{curr} | Warning: pefile failed - {str(e)}".lstrip(" | ")

        # Step C: Deep Reversing — r2ghidra Decompilation + Targeted XREF
        # Collects function addresses for concolic execution in Step D
        concolic_targets: List[Dict[str, Any]] = []

        try:
            r2 = r2pipe.open(file_path)
            
            # Prevent r2ghidra from hanging on text/unstructured files
            info = r2.cmdj("iIj")
            if info and info.get("bintype", "any") == "any":
                r2.quit()
                result["status"] = f"{result['status']} | Warning: Not a structured binary, skipping deep decompilation"
                return result

            r2.cmd("aa")  # Basic analysis (faster than aaa)

            # String Filtering via Regex (Kill the Noise)
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
                        result["static_features"]["high_value_strings"].append(string_val)

            # Extract list of exported functions
            exports_json = r2.cmdj("iEj")
            if exports_json:
                for exp in exports_json:
                    if "name" in exp:
                        all_strings.append(f"EXPORT:{exp['name']}")

            # Decompile entrypoint via r2ghidra
            r2.cmd("s entry0")
            entry_addr = r2.cmdj("sj") or 0
            try:
                disasm_json = r2.cmdj("pdgj")
                if disasm_json and isinstance(disasm_json, dict) and "code" in disasm_json:
                    code = disasm_json["code"]
                    if len(code) > 2000: code = code[:2000] + "\n// [TRUNCATED]"
                    
                    func_record = {
                        "name": "entry0",
                        "decompiled_c": code,
                        "symbolic_resolved_strings": []
                    }
                    result["static_features"]["functions"].append(func_record)

                    # Flag for concolic execution if obfuscation patterns are present
                    if _has_obfuscation_markers(code):
                        concolic_targets.append({
                            "func_index": len(result["static_features"]["functions"]) - 1,
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
                                            if len(code) > 2000: code = code[:2000] + "\n// [TRUNCATED]"
                                            
                                            func_record = {
                                                "name": f"func_{imp_name}_0x{call_addr:08x}",
                                                "decompiled_c": code,
                                                "symbolic_resolved_strings": []
                                            }
                                            result["static_features"]["functions"].append(func_record)

                                            if _has_obfuscation_markers(code):
                                                concolic_targets.append({
                                                    "func_index": len(result["static_features"]["functions"]) - 1,
                                                    "start_addr": call_addr
                                                })
                                    except Exception:
                                        pass

            r2.quit()
        except Exception as e:
            curr = result["status"]
            result["status"] = f"{curr} | Warning: r2pipe failed - {str(e)}".lstrip(" | ")

        # Step D: Concolic Execution — Resolve obfuscated strings via angr
        if concolic_targets:
            try:
                for target in concolic_targets:
                    resolved = resolve_with_timeout(
                        binary_path=file_path,
                        start_addr=target["start_addr"],
                        timeout=15
                    )
                    if resolved:
                        idx = target["func_index"]
                        result["static_features"]["functions"][idx]["symbolic_resolved_strings"] = resolved
                        # Also feed resolved strings into the global IOC pool
                        all_strings.extend(resolved)
                        result["static_features"]["high_value_strings"].extend(resolved)
                        logger.info(f"[Concolic] Resolved {len(resolved)} strings at 0x{target['start_addr']:08x}")
            except Exception as e:
                curr = result["status"]
                result["status"] = f"{curr} | Warning: Concolic engine failed - {str(e)}".lstrip(" | ")

        # Step E: Semantic Provenance Engine
        try:
            provenance_data = self.provenance_engine.analyze_delta(all_strings, all_imports)
            result["provenance"] = provenance_data
        except Exception as e:
            curr = result["status"]
            result["status"] = f"{curr} | Warning: Provenance Engine failed - {str(e)}".lstrip(" | ")

        return result


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
