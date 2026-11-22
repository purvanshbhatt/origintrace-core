"""
OriginTrace — Script Extractor

Handles malicious interpreted scripts: Python, JavaScript, Shell, PowerShell,
Batch. Skips binary toolchains entirely. Instead uses AST parsing (Python),
regex pattern matching, Shannon entropy, and IOC extraction to produce a
ScriptFeatures schema for the analysis agents.
"""
import ast
import logging
import math
import re
from collections import Counter
from typing import Dict, Any, List, Sequence

from extractors.ioc import BASE64_RE, find_iocs

logger = logging.getLogger("origintrace.script_extractor")

MAX_SOURCE_BYTES = 5 * 1024 * 1024   # bound regex/AST work on huge inputs
MAX_RAW_SOURCE_CHARS = 3000          # what is forwarded to the LLM
MAX_BLOBS = 20
MAX_BLOB_CHARS = 200
MAX_CALL_CHARS = 80

# Suspicious call patterns by language. The whole match is reported, so
# avoid capture groups that would narrow what the analyst sees.
SUSPICIOUS_PYTHON = [
    # (?<![\w.]) skips attribute calls such as re.compile() and model.eval().
    re.compile(r'(?<![\w.])eval\s*\('),
    re.compile(r'(?<![\w.])exec\s*\('),
    re.compile(r'\bos\.system\s*\('),
    re.compile(r'\bos\.popen\s*\('),
    re.compile(r'\bsubprocess\.\w+\s*\('),
    re.compile(r'\bctypes\.\w+'),
    re.compile(r'(?<![\w.])compile\s*\('),
    re.compile(r'\b__import__\s*\('),
    re.compile(r'\bgetattr\s*\('),
    re.compile(r'\bmarshal\.loads\s*\('),
    re.compile(r'\bsocket\.\w+'),
    re.compile(r'\burllib\.request\b'),
    re.compile(r'\brequests\.(?:get|post|put|delete)\s*\('),
]

SUSPICIOUS_JS = [
    re.compile(r'\beval\s*\('),
    re.compile(r'\bFunction\s*\('),
    re.compile(r'\bchild_process\b'),
    re.compile(r'\brequire\s*\(\s*["\']fs["\']\s*\)'),
    re.compile(r'\brequire\s*\(\s*["\']net["\']\s*\)'),
    re.compile(r'\bBuffer\.from\s*\('),
    re.compile(r'\batob\s*\('),
    re.compile(r'\bprocess\.env\b'),
    re.compile(r'\bsetTimeout\s*\(\s*function'),
    re.compile(r'\bnew\s+WebSocket\s*\('),
]

SUSPICIOUS_SHELL = [
    re.compile(r'\bcurl\s'),
    re.compile(r'\bwget\s'),
    re.compile(r'\bchmod\s+\+x'),
    re.compile(r'/dev/(?:tcp|udp)/[\w.\-]+/\d+'),
    re.compile(r'\bbash\s+-i\b'),
    re.compile(r'\bnc(?:at)?\s+(?:-\w+\s+)*-[ec]\b'),
    re.compile(r'\bbase64\s+(?:-d|--decode)\b'),
    re.compile(r'\bcrontab\b'),
    re.compile(r'\biptables\b'),
    re.compile(r'\bdd\s+if='),
    re.compile(r'\bmkfifo\b'),
    re.compile(r'\bpython[23]?\s+-c\b'),
    re.compile(r'\bperl\s+-e\b'),
]

SUSPICIOUS_POWERSHELL = [
    re.compile(r'\bIEX\b', re.IGNORECASE),
    re.compile(r'\bInvoke-Expression\b', re.IGNORECASE),
    re.compile(r'\bInvoke-WebRequest\b', re.IGNORECASE),
    re.compile(r'\bInvoke-RestMethod\b', re.IGNORECASE),
    re.compile(r'\.DownloadString\s*\(', re.IGNORECASE),
    re.compile(r'\.DownloadFile\s*\(', re.IGNORECASE),
    re.compile(r'(?<![\w-])-(?:EncodedCommand|enc|ec)\b', re.IGNORECASE),
    re.compile(r'\bFromBase64String\b', re.IGNORECASE),
    re.compile(r'\bNew-Object\s+(?:System\.)?Net\.WebClient\b', re.IGNORECASE),
    re.compile(r'\bStart-Process\b', re.IGNORECASE),
    re.compile(r'\b(?:Add|Set)-MpPreference\b', re.IGNORECASE),
    re.compile(r'(?<![\w-])-(?:w|WindowStyle)\s+hidden\b', re.IGNORECASE),
    re.compile(r'(?<![\w-])-(?:ep|ExecutionPolicy)\s+bypass\b', re.IGNORECASE),
    re.compile(r'\bReflection\.Assembly\b', re.IGNORECASE),
]

SUSPICIOUS_BATCH = [
    re.compile(r'\bpowershell(?:\.exe)?\b', re.IGNORECASE),
    re.compile(r'\bcmd(?:\.exe)?\s+/[ck]\b', re.IGNORECASE),
    re.compile(r'\bcertutil\b[^\r\n]{0,40}-(?:urlcache|decode)\b', re.IGNORECASE),
    re.compile(r'\bbitsadmin\b', re.IGNORECASE),
    re.compile(r'\breg\s+add\b', re.IGNORECASE),
    re.compile(r'\bschtasks\b', re.IGNORECASE),
    re.compile(r'\bvssadmin\b', re.IGNORECASE),
    re.compile(r'\bmshta\b', re.IGNORECASE),
    re.compile(r'\brundll32\b', re.IGNORECASE),
    re.compile(r'\bregsvr32\b', re.IGNORECASE),
    re.compile(r'\bwmic\b', re.IGNORECASE),
    re.compile(r'\bnet\s+user\b', re.IGNORECASE),
]

PATTERNS_BY_LANGUAGE: Dict[str, Sequence[re.Pattern]] = {
    "python": SUSPICIOUS_PYTHON,
    "javascript": SUSPICIOUS_JS,
    "shell": SUSPICIOUS_SHELL,
    "powershell": SUSPICIOUS_POWERSHELL + SUSPICIOUS_BATCH,
    "batch": SUSPICIOUS_BATCH + SUSPICIOUS_POWERSHELL,
}
# Unknown language: scan with every pattern set.
ALL_PATTERNS: Sequence[re.Pattern] = (
    SUSPICIOUS_PYTHON + SUSPICIOUS_JS + SUSPICIOUS_SHELL + SUSPICIOUS_POWERSHELL + SUSPICIOUS_BATCH
)

EXTENSION_LANGUAGES = {
    "py": "python", "pyw": "python",
    "js": "javascript", "mjs": "javascript", "cjs": "javascript",
    "ts": "javascript",
    "sh": "shell", "bash": "shell",
    "ps1": "powershell", "psm1": "powershell",
    "bat": "batch", "cmd": "batch",
}

_SHEBANG_SHELL_RE = re.compile(r'\b(?:ba|da|z|k|a)?sh\b')
_JS_HINT_RE = re.compile(
    r'\brequire\s*\(|\bmodule\.exports\b|\bconsole\.log\s*\(|=>'
    r'|^\s*(?:const|let|var)\s+\w+\s*=|^\s*import\s+.*\sfrom\s+["\']',
    re.MULTILINE,
)
_PYTHON_HINT_RE = re.compile(
    r'^\s*(?:import\s+\w+|from\s+[\w.]+\s+import\s+\w+|def\s+\w+\s*\()', re.MULTILINE
)
_POWERSHELL_HINT_RE = re.compile(r'\b(?:Invoke-\w+|New-Object|Write-Host)\b|\$env:', re.IGNORECASE)
_BATCH_HINT_RE = re.compile(r'^\s*(?:@echo\s+off|setlocal\b|rem\s)', re.IGNORECASE | re.MULTILINE)

_JS_REQUIRE_RE = re.compile(r'\brequire\s*\(\s*["\']([^"\']+)["\']\s*\)')
_JS_IMPORT_RE = re.compile(r'\bimport\s+(?:[^"\';]*?\sfrom\s+)?["\']([^"\']+)["\']')
_JS_DYNAMIC_IMPORT_RE = re.compile(r'\bimport\s*\(\s*["\']([^"\']+)["\']\s*\)')
_PY_IMPORT_FALLBACK_RE = re.compile(r'^\s*(?:from\s+(\S+)\s+)?import\s+(.+)', re.MULTILINE)


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string as an obfuscation heuristic."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    # The schema caps the score at 8 bits; exotic alphabets can exceed it.
    return round(min(entropy, 8.0), 3)


def _read_text(file_path: str) -> str:
    """Read a script, honouring UTF-16 BOMs (common for PowerShell)."""
    with open(file_path, "rb") as f:
        data = f.read(MAX_SOURCE_BYTES)
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.decode("utf-8", errors="replace")


def _detect_language(source: str, filename: str) -> str:
    """Heuristic language detection from filename extension and content."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in EXTENSION_LANGUAGES:
        return EXTENSION_LANGUAGES[ext]

    # Shebang line
    if source.startswith("#!"):
        interpreter = source.split("\n", 1)[0][:200].lower()
        if "python" in interpreter:
            return "python"
        if "node" in interpreter:
            return "javascript"
        if "pwsh" in interpreter or "powershell" in interpreter:
            return "powershell"
        if _SHEBANG_SHELL_RE.search(interpreter):
            return "shell"

    # Content-based fallback
    head = source[:2000]
    if _JS_HINT_RE.search(head):
        return "javascript"
    if _PYTHON_HINT_RE.search(head):
        return "python"
    if _POWERSHELL_HINT_RE.search(head):
        return "powershell"
    if _BATCH_HINT_RE.search(head):
        return "batch"

    return "unknown"


def _unique(items: List[str]) -> List[str]:
    """De-duplicate while preserving first-seen order."""
    return list(dict.fromkeys(items))


class ScriptExtractor:
    """Extraction pipeline for interpreted malicious scripts."""

    def extract(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Analyze a script file for malicious indicators.
        Returns a dict compatible with ScriptFeatures schema.
        """
        try:
            source = _read_text(file_path)
        except OSError as e:
            logger.error(f"[ScriptExtractor] Failed to read file: {e}")
            return self._empty_result("unknown")

        language = _detect_language(source, filename)

        result = {
            "language": language,
            "raw_source": source[:MAX_RAW_SOURCE_CHARS] + ("\n# [TRUNCATED]" if len(source) > MAX_RAW_SOURCE_CHARS else ""),
            "ast_imports": [],
            "suspicious_calls": [],
            "encoded_blobs": [],
            "obfuscation_score": _shannon_entropy(source),
            "high_value_strings": [],
        }

        # ── Import extraction (AST for Python, regex for JavaScript) ──
        if language == "python":
            result["ast_imports"] = self._extract_python_imports(source)
        elif language == "javascript":
            result["ast_imports"] = self._extract_js_imports(source)

        # ── Suspicious call detection ──
        calls: List[str] = []
        for pattern in PATTERNS_BY_LANGUAGE.get(language, ALL_PATTERNS):
            for match in pattern.finditer(source):
                call_str = " ".join(match.group(0).split())[:MAX_CALL_CHARS]
                if call_str:
                    calls.append(call_str)
        result["suspicious_calls"] = _unique(calls)

        # ── Encoded blob detection ──
        seen_blobs = set()
        for match in BASE64_RE.finditer(source):
            blob = match.group(0)
            if blob in seen_blobs:
                continue
            seen_blobs.add(blob)
            result["encoded_blobs"].append(blob[:MAX_BLOB_CHARS])
            if len(result["encoded_blobs"]) >= MAX_BLOBS:
                break

        # ── IOC string extraction ──
        result["high_value_strings"] = find_iocs(source)

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
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            # Fallback: regex-based extraction for obfuscated/invalid Python
            for match in _PY_IMPORT_FALLBACK_RE.finditer(source):
                from_mod = match.group(1) or ""
                imported = match.group(2)
                for name in imported.split(","):
                    name = name.strip().split(" as ")[0].strip()
                    if not name:
                        continue
                    if from_mod:
                        imports.append(f"{from_mod}.{name}")
                    else:
                        imports.append(name)
        return _unique(imports)

    def _extract_js_imports(self, source: str) -> List[str]:
        """Regex-based extraction of require() and import statements from JavaScript."""
        imports = []
        # CommonJS: require('module')
        imports.extend(match.group(1) for match in _JS_REQUIRE_RE.finditer(source))
        # ES modules: import x from 'module' / import 'module'
        imports.extend(match.group(1) for match in _JS_IMPORT_RE.finditer(source))
        # Dynamic: import('module')
        imports.extend(match.group(1) for match in _JS_DYNAMIC_IMPORT_RE.finditer(source))
        return _unique(imports)

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
