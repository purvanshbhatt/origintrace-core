import pefile
import hashlib
import re

def extract_local_features(file_path: str) -> dict:
    """Extracts static features from a Windows PE binary."""
    features = {
        "hashes": {},
        "imports": [],
        "strings": [],
        "status": "success"
    }

    try:
        # 1. Calculate Hashes
        with open(file_path, "rb") as f:
            data = f.read()
            features["hashes"]["sha256"] = hashlib.sha256(data).hexdigest()
            features["hashes"]["md5"] = hashlib.md5(data).hexdigest()

        # 2. Extract ASCII Strings (Limit to 500 longest to save LLM tokens)
        strings = re.findall(b"[ -~]{6,}", data)
        decoded_strings = [s.decode('utf-8') for s in strings]
        # Sort by length descending, take top 500
        features["strings"] = sorted(decoded_strings, key=len, reverse=True)[:500]

        # 3. Parse PE Imports
        pe = pefile.PE(data=data)
        features["hashes"]["imphash"] = pe.get_imphash()
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8') if entry.dll else "unknown_dll"
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8')
                        features["imports"].append(f"{dll_name}:{func_name}")

    except Exception as e:
        features["status"] = f"error: {str(e)}"

    return features
