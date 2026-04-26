import pefile
import r2pipe
import math
import hashlib
import json
import logging

logger = logging.getLogger(__name__)

class BinaryExtractor:
    @staticmethod
    def extract_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    @staticmethod
    def extract(file_path: str, filename: str) -> dict:
        features = {
            "filename": filename,
            "hashes": {},
            "pe_metadata": {
                "imports": [],
                "exports": [],
                "sections": [],
            },
            "disassembly": {},
            "strings": [],
            "status": "success",
            "warnings": []
        }

        with open(file_path, "rb") as f:
            data = f.read()
            features["hashes"]["sha256"] = hashlib.sha256(data).hexdigest()
            features["hashes"]["md5"] = hashlib.md5(data).hexdigest()

        # Phase 1: pefile Extraction
        try:
            pe = pefile.PE(file_path)
            features["hashes"]["imphash"] = pe.get_imphash()
            
            # Analyze Sections (looking for high entropy/packing)
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                sec_entropy = section.get_entropy()
                features["pe_metadata"]["sections"].append({
                    "name": sec_name,
                    "entropy": sec_entropy,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData
                })

            # Analyze Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore') if entry.dll else "unknown"
                    for imp in entry.imports:
                        if imp.name:
                            features["pe_metadata"]["imports"].append(f"{dll_name}:{imp.name.decode('utf-8', errors='ignore')}")

            # Analyze Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        features["pe_metadata"]["exports"].append(exp.name.decode('utf-8', errors='ignore'))
                    
        except pefile.PEFormatError:
            features["warnings"].append("Not a valid PE file or corrupted headers.")
        except Exception as e:
            features["warnings"].append(f"PE Analysis Error: {str(e)}")

        # Phase 2: radare2 Extractions
        try:
            r2 = r2pipe.open(file_path)
            r2.cmd("aaa") # Analyze all

            # 1. Grab Strings (izzj returns decoded strings)
            strings_json = r2.cmd("izzj")
            if strings_json:
                strings_data = json.loads(strings_json)
                unique_strings = list({s.get("string") for s in strings_data if s.get("string") and len(s.get("string")) > 5})
                # Cap the number of strings to not overflow LLM context
                features["strings"] = sorted(unique_strings, key=len, reverse=True)[:150]

            # 2. Grab Entrypoint Disassembly
            try:
                disasm = r2.cmd("pdf @ entry0")
                if disasm:
                    # Truncate disassembly to preserve context limits
                    features["disassembly"]["entry0"] = disasm[:2000]
            except Exception as e:
                features["warnings"].append(f"Could not disassemble entry0: {str(e)}")
            
            r2.quit()
        except Exception as e:
            features["warnings"].append(f"Radare2 Analysis Error: {str(e)}")

        if features["warnings"] and not features["strings"]:
            features["status"] = "partial_failure"

        return features
