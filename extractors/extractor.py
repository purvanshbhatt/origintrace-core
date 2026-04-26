import hashlib
import re
import pefile
import r2pipe
from typing import Dict, Any

from extractors.provenance import ProvenanceEngine

class MasterBinaryExtractor:
    def __init__(self):
        self.provenance_engine = ProvenanceEngine()

    async def extract_all(self, file_path: str, filename: str) -> Dict[str, Any]:
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
                "entrypoint_disassembly": "",
                "suspicious_functions": [],
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

        # Step C: Deep Reversing (Radare2 / r2pipe)
        try:
            r2 = r2pipe.open(file_path)
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
                        # Append exports into strings/features logic to pass into provenance
                        all_strings.append(f"EXPORT:{exp['name']}")

            # Extract raw disassembly of the entrypoint
            r2.cmd("s entry0")
            disasm_json = r2.cmdj("pdfj")
            if disasm_json and "ops" in disasm_json:
                disasm_lines = []
                # Limit to 50 lines to strictly conserve LLM context tokens
                for op in disasm_json["ops"][:50]:
                    if "opcode" in op:
                        disasm_lines.append(f"0x{op.get('offset', 0):08x}  {op['opcode']}")
                
                result["static_features"]["entrypoint_disassembly"] = "\n".join(disasm_lines)

            # Advanced: Targeted r2pipe Disassembly for suspicious APIs
            suspicious_apis = ["VirtualAlloc", "CryptEncrypt", "InternetOpen", "CreateProcess"]
            imports_json = r2.cmdj("iij")
            if imports_json:
                for imp in imports_json:
                    imp_name = imp.get("name", "")
                    if any(sus_api.lower() in imp_name.lower() for sus_api in suspicious_apis):
                        # Find xrefs to this import
                        xrefs = r2.cmdj(f"axtj sym.imp.{imp_name}")
                        if not xrefs:
                            xrefs = r2.cmdj(f"axtj {imp_name}")
                        if xrefs:
                            # Limit to first 3 xrefs per API to keep context lean
                            for xref in xrefs[:3]:
                                call_addr = xref.get("from", 0)
                                if call_addr:
                                    r2.cmd(f"s {call_addr}")
                                    func_disasm = r2.cmdj("pdfj")
                                    if func_disasm and "ops" in func_disasm:
                                        lines = [f"; XREF to {imp_name} at 0x{call_addr:08x}"]
                                        for op in func_disasm["ops"][:30]:
                                            if "opcode" in op:
                                                lines.append(f"0x{op.get('offset', 0):08x}  {op['opcode']}")
                                        result["static_features"]["suspicious_functions"].append("\n".join(lines))

            r2.quit()
        except Exception as e:
            curr = result["status"]
            result["status"] = f"{curr} | Warning: r2pipe failed - {str(e)}".lstrip(" | ")

        # Step D: Semantic Provenance Engine
        try:
            # Match unified signature (strings + imports/exports) against local vector DB
            provenance_data = self.provenance_engine.analyze_delta(all_strings, all_imports)
            result["provenance"] = provenance_data
        except Exception as e:
            curr = result["status"]
            result["status"] = f"{curr} | Warning: Provenance Engine failed - {str(e)}".lstrip(" | ")

        return result
