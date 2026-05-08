"""
OriginTrace — Script Extractor

Handles malicious interpreted scripts: Python, JavaScript, Shell, PowerShell.
Skips binary toolchains entirely. Instead uses AST parsing (Python), regex
pattern matching, Shannon entropy, and IOC extraction to produce a
ScriptFeatures schema for the LLM.
"""
import ast
import math
import re
import logging
from collections import Counter
from typing import Dict, Any, List

logger = logging.getLogger("origintrace.script_extractor")

# Suspicious function/method call patterns by language
SUSPICIOUS_PYTHON = [
    re.compile(r'\beval\s*\('),
    re.compile(r'\bexec\s*\('),
    re.compile(r'\bos\.system\s*\('),
    re.compile(r'\bsubprocess\.\w+\s*\('),
    re.compile(r'\bctypes\.\w+'),
    re.compile(r'\bcompile\s*\('),
    re.compile(r'\b__import__\s*\('),
    re.compile(r'\bgetattr\s*\('),
    re.compile(r'\bsocket\.\w+'),
    re.compile(r'\burllib\.request'),
    re.compile(r'\brequests\.(get|post|put)\s*\('),
]

SUSPICIOUS_JS = [
    re.compile(r'\beval\s*\('),
    re.compile(r'\bFunction\s*\('),
    re.compile(r'\bchild_process'),
    re.compile(r'\brequire\s*\(\s*["\']fs["\']\s*\)'),
    re.compile(r'\brequire\s*\(\s*["\']net["\']\s*\)'),
    re.compile(r'\bBuffer\.from\s*\('),
    re.compile(r'\bprocess\.env'),
    re.compile(r'\bsetTimeout\s*\(\s*function'),
    re.compile(r'\bnew\s+WebSocket\s*\('),
]

SUSPICIOUS_SHELL = [
    re.compile(r'\bcurl\s+'),
    re.compile(r'\bwget\s+'),
    re.compile(r'\bchmod\s+\+x'),
    re.compile(r'\b/dev/tcp/'),
    re.compile(r'\bnc\s+(-e|-c)'),
    re.compile(r'\bbase64\s+(-d|--decode)'),
    re.compile(r'\bcrontab\b'),
    re.compile(r'\biptables\b'),
    re.compile(r'\bdd\s+if='),
]

# IOC patterns universal across languages
IOC_PATTERNS = [
    re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'),           # IPv4
    re.compile(r'https?://[^\s"\'`]+'),                       # URLs
    re.compile(r'[A-Za-z]:\\\\[^\s"\']+'),                    # Windows paths
    re.compile(r'HK[LC]U\\\\[^\s"\']+'),                     # Registry keys
    re.compile(r'/etc/passwd|/etc/shadow|/tmp/\.\w+'),        # Linux sensitive paths
]

# Base64 blob detector (standalone encoded payloads)
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string as an obfuscation heuristic."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 3)


def _detect_language(source: str, filename: str) -> str:
    """Heuristic language detection from filename extension and content."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    ext_map = {
        "py": "python", "pyw": "python",
        "js": "javascript", "mjs": "javascript", "cjs": "javascript",
        "ts": "javascript",
        "sh": "shell", "bash": "shell",
        "ps1": "powershell", "psm1": "powershell",
        "bat": "shell", "cmd": "shell",
    }
    if ext in ext_map:
        return ext_map[ext]

    # Content-based fallback
    if source.startswith("#!/") and ("python" in source[:100] or "python3" in source[:100]):
        return "python"
    if source.startswith("#!/") and ("bash" in source[:100] or "sh" in source[:100]):
        return "shell"
    if "require(" in source[:500] or "import " in source[:500] and "from " in source[:500]:
        return "javascript" if "require(" in source[:500] else "python"

    return "unknown"


class ScriptExtractor:
    """Extraction pipeline for interpreted malicious scripts."""

    def extract(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Analyze a script file for malicious indicators.
        Returns a dict compatible with ScriptFeatures schema.
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception as e:
            logger.error(f"[ScriptExtractor] Failed to read file: {e}")
            return self._empty_result("unknown")

        language = _detect_language(source, filename)

        result = {
            "language": language,
            "raw_source": source[:3000] + ("\n# [TRUNCATED]" if len(source) > 3000 else ""),
            "ast_imports": [],
            "suspicious_calls": [],
            "encoded_blobs": [],
            "obfuscation_score": _shannon_entropy(source),
            "high_value_strings": [],
        }

        # ── AST-based import extraction (Python only) ──
        if language == "python":
            result["ast_imports"] = self._extract_python_imports(source)
            patterns = SUSPICIOUS_PYTHON
        elif language == "javascript":
            result["ast_imports"] = self._extract_js_imports(source)
            patterns = SUSPICIOUS_JS
        elif language in ("shell", "powershell"):
            patterns = SUSPICIOUS_SHELL
        else:
            patterns = SUSPICIOUS_PYTHON + SUSPICIOUS_JS  # broad scan

        # ── Suspicious call detection ──
        for pattern in patterns:
            matches = pattern.findall(source)
            for match in matches:
                call_str = match.strip()
                if call_str and call_str not in result["suspicious_calls"]:
                    result["suspicious_calls"].append(call_str)

        # ── Encoded blob detection ──
        for match in BASE64_PATTERN.finditer(source):
            blob = match.group()
            if blob not in result["encoded_blobs"]:
                result["encoded_blobs"].append(blob[:200])  # cap length

        # ── IOC string extraction ──
        for pattern in IOC_PATTERNS:
            for match in pattern.finditer(source):
                val = match.group()
                if val not in result["high_value_strings"]:
                    result["high_value_strings"].append(val)

        return result

    def _extract_python_imports(self, source: str) -> List[str]:
        """Use Python's AST to reliably extract import statements."""
        imports = []
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        imports.append(f"{module}.{alias.name}")
        except SyntaxError:
            # Fallback: regex-based extraction for obfuscated/invalid Python
            import_re = re.compile(r'^\s*(?:from\s+(\S+)\s+)?import\s+(.+)', re.MULTILINE)
            for match in import_re.finditer(source):
                from_mod = match.group(1) or ""
                imported = match.group(2)
                for name in imported.split(","):
                    name = name.strip().split(" as ")[0].strip()
                    if from_mod:
                        imports.append(f"{from_mod}.{name}")
                    else:
                        imports.append(name)
        return imports

    def _extract_js_imports(self, source: str) -> List[str]:
        """Regex-based extraction of require() and import statements from JavaScript."""
        imports = []
        # CommonJS: require('module')
        for match in re.finditer(r'require\s*\(\s*["\']([^"\']+)["\']\s*\)', source):
            imports.append(match.group(1))
        # ES6: import ... from 'module'
        for match in re.finditer(r'import\s+.*?\s+from\s+["\']([^"\']+)["\']', source):
            imports.append(match.group(1))
        return imports

    def _empty_result(self, language: str) -> Dict[str, Any]:
        return {
            "language": language,
            "raw_source": "",
            "ast_imports": [],
            "suspicious_calls": [],
            "encoded_blobs": [],
            "obfuscation_score": 0.0,
            "high_value_strings": [],
        }
