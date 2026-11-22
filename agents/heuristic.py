"""
OriginTrace — Offline Heuristic Agents

Deterministic, dependency-free stand-ins for the Gemini agents. They map
extracted features to MITRE ATT&CK techniques with a rule table and generate
YARA / Sigma rules from the extracted indicators.

They serve two purposes:
  1. The pipeline works end to end without an API key (local development,
     air-gapped triage).
  2. They are the fallback when a Gemini call fails, so one bad LLM response
     does not discard a completed extraction.

The output is rule-based, not reasoned: every finding cites the exact
indicator that triggered it, and a clean result is never reported as "safe".
"""
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Pattern, Sequence, Tuple

from agents.context import attribution_from_provenance, level_from_score
from extractors.ioc import IPV4_RE, REGISTRY_RE, UNIX_PATH_RE, URL_RE, WINDOWS_PATH_RE
from models import AnalystReport, DetectionArtifacts, MitreTechnique

ENGINE_NAME = "heuristic"

PACKED_SECTION_ENTROPY = 7.2    # sections above this are packed or encrypted
OBFUSCATED_SOURCE_ENTROPY = 5.8  # plain source code sits around 4.3 - 5.2
MAX_EVIDENCE_ITEMS = 3
MAX_EVIDENCE_CHARS = 100

MAX_STRONG_STRINGS = 12
MAX_WEAK_STRINGS = 8
MAX_BLOB_STRINGS = 3
MIN_YARA_STRING_CHARS = 6
MAX_YARA_STRING_CHARS = 200
BLOB_PREFIX_CHARS = 48
MAX_SIGMA_INDICATORS = 10

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]

_ENTROPY_RE = re.compile(r"Entropy:\s*([0-9.]+)")
_AUTOEXEC_RE = re.compile(
    r"\b(?:AutoOpen|Auto_Open|AutoExec|AutoClose|Document_Open|Document_Close|Workbook_Open)\b", re.IGNORECASE
)
_NETWORK_API_RE = re.compile(
    r"requests\.|urllib|http\.client|\bfetch\s*\(|XMLHttpRequest|axios|InternetOpen|WinHttp|HttpSendRequest"
    r"|\bcurl\b|\bwget\b|WebClient|Invoke-WebRequest|Invoke-RestMethod|URLDownloadToFile|\bhttps?\.request\b",
    re.IGNORECASE,
)


def _unique(items: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(item for item in items if item))


def _clip(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _strings(payload: Dict[str, Any], key: str) -> List[str]:
    value = payload.get(key)
    return [str(item) for item in value] if isinstance(value, list) else []


# ─── Indicator view ──────────────────────────────────────────

@dataclass
class IndicatorView:
    """Flat, type-agnostic view of an ExtractionResult for rule matching."""
    filename: str
    file_type: str
    language: str
    imports: List[str]
    strings: List[str]
    calls: List[str]
    source: str
    blobs: List[str]
    resolved_strings: List[str]
    max_section_entropy: float
    script_entropy: float
    has_macros: bool
    extension_mismatch: bool
    provenance: Dict[str, Any]

    @classmethod
    def from_features(cls, features: Dict[str, Any]) -> "IndicatorView":
        features = features or {}
        metadata = features.get("metadata") or {}
        binary = features.get("binary_features") or {}
        script = features.get("script_features") or {}
        document = features.get("document_features") or {}
        functions = [f for f in (binary.get("functions") or []) if isinstance(f, dict)]

        resolved = _unique(s for f in functions for s in (f.get("symbolic_resolved_strings") or []))
        entropies = [float(m) for section in _strings(binary, "sections") for m in _ENTROPY_RE.findall(section)]
        source_parts = [script.get("raw_source") or "", document.get("macro_source") or ""]
        source_parts += [f.get("decompiled_c") or "" for f in functions]

        return cls(
            filename=str(metadata.get("filename") or "sample"),
            file_type=str(features.get("file_type") or metadata.get("file_type") or "unknown"),
            language=str(script.get("language") or ""),
            imports=_unique(_strings(binary, "imports") + _strings(script, "ast_imports")),
            strings=_unique(
                _strings(binary, "high_value_strings") + _strings(script, "high_value_strings")
                + _strings(document, "high_value_strings") + _strings(document, "embedded_urls") + resolved
            ),
            calls=_unique(_strings(script, "suspicious_calls") + _strings(document, "suspicious_keywords")),
            source="\n".join(part for part in source_parts if part),
            blobs=_strings(script, "encoded_blobs"),
            resolved_strings=resolved,
            max_section_entropy=max(entropies, default=0.0),
            script_entropy=float(script.get("obfuscation_score") or 0.0),
            has_macros=bool(document.get("has_macros")),
            extension_mismatch=bool(metadata.get("extension_mismatch")),
            provenance=features.get("provenance") or {},
        )

    def first_hit(self, pattern: Pattern[str]) -> Optional[str]:
        """Describe the first place ``pattern`` matches, most specific first."""
        for item in self.imports:
            if pattern.search(item):
                return f"import: {_clip(item)}"
        match = pattern.search(self.source)
        if match:
            start = self.source.rfind("\n", 0, match.start()) + 1
            end = self.source.find("\n", match.end())
            line = self.source[start: end if end != -1 else len(self.source)]
            return f"source: {_clip(line)}"
        for label, bucket in (("call", self.calls), ("string", self.strings)):
            for item in bucket:
                if pattern.search(item):
                    return f"{label}: {_clip(item)}"
        return None


# ─── Rule table ──────────────────────────────────────────────

@dataclass(frozen=True)
class Rule:
    """One ATT&CK technique and the indicators that imply it."""
    technique_id: str
    name: str
    tactic: str
    weight: int
    patterns: Tuple[Pattern[str], ...] = ()
    min_matches: int = 1
    file_types: Optional[Tuple[str, ...]] = None
    languages: Optional[Tuple[str, ...]] = None
    predicate: Optional[Callable[[IndicatorView], Optional[str]]] = None

    def evaluate(self, view: IndicatorView) -> Optional[str]:
        """Return an evidence string when the rule fires, else None."""
        if self.file_types and view.file_type not in self.file_types:
            return None
        if self.languages and view.language not in self.languages:
            return None

        evidence: List[str] = []
        if self.predicate:
            note = self.predicate(view)
            if note:
                evidence.append(note)

        hits = [hit for hit in (view.first_hit(pattern) for pattern in self.patterns) if hit]
        if len(hits) >= self.min_matches:
            evidence.extend(hits)

        if not evidence:
            return None
        return "; ".join(_unique(evidence)[:MAX_EVIDENCE_ITEMS])


def _p(*expressions: str) -> Tuple[Pattern[str], ...]:
    return tuple(re.compile(expression, re.IGNORECASE) for expression in expressions)


def _has_macros(view: IndicatorView) -> Optional[str]:
    return "document contains VBA macros" if view.has_macros else None


def _autoexec_macro(view: IndicatorView) -> Optional[str]:
    if not view.has_macros:
        return None
    for text in view.calls + [view.source]:
        match = _AUTOEXEC_RE.search(text)
        if match:
            return f"macro runs automatically via {match.group(0)}"
    return None


def _obfuscation(view: IndicatorView) -> Optional[str]:
    notes = []
    if view.blobs:
        notes.append(f"{len(view.blobs)} encoded blob(s), e.g. {_clip(view.blobs[0], 40)}")
    if view.max_section_entropy >= PACKED_SECTION_ENTROPY:
        notes.append(f"section entropy {view.max_section_entropy:.2f} (packed or encrypted)")
    if view.script_entropy >= OBFUSCATED_SOURCE_ENTROPY:
        notes.append(f"source entropy {view.script_entropy:.2f}")
    return "; ".join(notes) or None


def _resolved_strings(view: IndicatorView) -> Optional[str]:
    if not view.resolved_strings:
        return None
    return f"concolic execution decrypted: {_clip(view.resolved_strings[0])}"


def _web_c2(view: IndicatorView) -> Optional[str]:
    urls = [s for s in view.strings if URL_RE.match(s)]
    if not urls:
        return None
    api = view.first_hit(_NETWORK_API_RE)
    if not api:
        return None
    return f"URL {_clip(urls[0])} reachable via {api}"


def _masquerade(view: IndicatorView) -> Optional[str]:
    if not view.extension_mismatch:
        return None
    return f"extension of {view.filename} does not match its detected type ({view.file_type})"


def _supply_chain(view: IndicatorView) -> Optional[str]:
    attribution = attribution_from_provenance(view.provenance)
    injected = view.provenance.get("injected_artifacts") or []
    if not attribution.suspected_package or not injected:
        return None
    return (
        f"features resemble {attribution.suspected_package} ({attribution.ecosystem}) "
        f"with {len(injected)} artifact(s) outside its baseline"
    )


RULES: Tuple[Rule, ...] = (
    # ── Initial Access ──
    Rule("T1195.002", "Compromise Software Supply Chain", "Initial Access", 25, predicate=_supply_chain),
    # ── Execution ──
    Rule("T1204.002", "User Execution: Malicious File", "Execution", 25, predicate=_autoexec_macro),
    Rule("T1059.001", "PowerShell", "Execution", 20, _p(
        r"\bpowershell(?:\.exe)?\b", r"\bpwsh\b", r"\bInvoke-Expression\b", r"\bIEX\b",
        r"(?<![\w-])-(?:EncodedCommand|enc)\b")),
    Rule("T1059.003", "Windows Command Shell", "Execution", 10, _p(r"\bcmd(?:\.exe)?\s+/[ck]\b", r"\bcmd\.exe\b")),
    Rule("T1059.004", "Unix Shell", "Execution", 15, _p(
        r"\bbash\s+-[ic]\b", r"\bsh\s+-c\b", r"\|\s*(?:ba|da|z)?sh\b", r"(?<!#!)/bin/(?:ba|da|z)?sh\b")),
    Rule("T1059.005", "Visual Basic", "Execution", 20, predicate=_has_macros),
    Rule("T1059.006", "Python", "Execution", 20, _p(
        r"(?<![\w.])exec\s*\(", r"(?<![\w.])eval\s*\(", r"(?<![\w.])compile\s*\(",
        r"\b__import__\s*\(", r"\bmarshal\.loads\b"), languages=("python",)),
    Rule("T1059.007", "JavaScript", "Execution", 20, _p(
        r"(?<![\w.])eval\s*\(", r"\bFunction\s*\(", r"\bchild_process\b"), languages=("javascript",)),
    Rule("T1106", "Native API", "Execution", 10, _p(
        r"\bVirtualAlloc\b", r"\bVirtualProtect\b", r"\bCreateProcess[AW]?\b", r"\bWinExec\b",
        r"\bShellExecute(?:Ex)?[AW]?\b", r"\bctypes\.(?:windll|cdll|CDLL)\b")),
    # ── Persistence ──
    Rule("T1547.001", "Registry Run Keys / Startup Folder", "Persistence", 20, _p(r"CurrentVersion\\{1,2}Run")),
    Rule("T1053.003", "Scheduled Task/Job: Cron", "Persistence", 20, _p(r"\bcrontab\b", r"/etc/cron")),
    Rule("T1053.005", "Scheduled Task", "Persistence", 20, _p(r"\bschtasks\b", r"Register-ScheduledTask")),
    Rule("T1543.002", "Systemd Service", "Persistence", 15, _p(r"systemctl\s+enable", r"/etc/systemd/system")),
    Rule("T1546.004", "Unix Shell Configuration Modification", "Persistence", 15, _p(
        r">>\s*\S*\.(?:bashrc|bash_profile|profile|zshrc)\b")),
    # ── Defense Evasion ──
    Rule("T1055", "Process Injection", "Defense Evasion", 30, _p(
        r"VirtualAllocEx", r"WriteProcessMemory", r"CreateRemoteThread", r"NtCreateThreadEx",
        r"QueueUserAPC", r"NtUnmapViewOfSection", r"SetThreadContext", r"RtlCreateUserThread"), min_matches=2),
    Rule("T1027", "Obfuscated Files or Information", "Defense Evasion", 15, predicate=_obfuscation),
    Rule("T1027.007", "Dynamic API Resolution", "Defense Evasion", 10, _p(
        r"GetProcAddress", r"LoadLibrary"), min_matches=2),
    Rule("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion", 15, _p(
        r"\bb64decode\b", r"\bbase64\s+(?:-d|--decode)\b", r"\batob\s*\(", r"\bFromBase64String\b",
        r"Buffer\.from\([^)]*base64", r"\bcertutil\b.*-decode\b", r"\bbytes\.fromhex\b",
        r"\bcodecs\.decode\b", r"\bzlib\.decompress\b", r"\bunhexlify\b"), predicate=_resolved_strings),
    Rule("T1036.008", "Masquerade File Type", "Defense Evasion", 15, predicate=_masquerade),
    Rule("T1562.001", "Disable or Modify Tools", "Defense Evasion", 20, _p(
        r"(?:Add|Set)-MpPreference", r"DisableRealtimeMonitoring", r"setenforce\s+0")),
    Rule("T1562.004", "Disable or Modify System Firewall", "Defense Evasion", 15, _p(
        r"\biptables\b", r"netsh\s+(?:adv)?firewall", r"\bufw\s+disable\b")),
    Rule("T1564.003", "Hidden Window", "Defense Evasion", 10, _p(r"(?<![\w-])-(?:w|WindowStyle)\s+hidden\b")),
    Rule("T1622", "Debugger Evasion", "Defense Evasion", 10, _p(
        r"IsDebuggerPresent", r"CheckRemoteDebuggerPresent", r"NtQueryInformationProcess", r"\bptrace\s*\(")),
    Rule("T1222.002", "Linux and Mac File and Directory Permissions Modification", "Defense Evasion", 5, _p(
        r"\bchmod\s+(?:\+x|[0-7]{3,4})")),
    # ── Credential Access ──
    Rule("T1003.008", "/etc/passwd and /etc/shadow", "Credential Access", 20, _p(r"/etc/shadow")),
    Rule("T1552.001", "Credentials In Files", "Credential Access", 15, _p(
        r"\.aws/credentials", r"aws_secret_access_key", r"\.ssh/id_[a-z0-9]+", r"\.npmrc\b", r"\.pypirc\b",
        r"\.git-credentials")),
    Rule("T1555.003", "Credentials from Web Browsers", "Credential Access", 20, _p(
        r"Login Data", r"logins\.json", r"cookies\.sqlite")),
    # ── Discovery ──
    Rule("T1082", "System Information Discovery", "Discovery", 5, _p(
        r"\buname\s+-a\b", r"\bsysteminfo\b", r"GetComputerName", r"platform\.(?:node|uname)\s*\(",
        r"os\.hostname\s*\(", r"\bwhoami\b")),
    # ── Command and Control ──
    Rule("T1105", "Ingress Tool Transfer", "Command and Control", 20, _p(
        r"\bcurl\s", r"\bwget\s", r"URLDownloadToFile", r"\.DownloadString\b", r"\.DownloadFile\b",
        r"\bInvoke-WebRequest\b", r"\burlretrieve\b", r"\bbitsadmin\b", r"\bcertutil\b.*-urlcache",
        r"\bStart-BitsTransfer\b")),
    Rule("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", 10, predicate=_web_c2),
    Rule("T1095", "Non-Application Layer Protocol", "Command and Control", 20, _p(
        r"/dev/(?:tcp|udp)/", r"\bsocket\.socket\s*\(", r"\bnc(?:at)?\s+(?:-\w+\s+)*-e\b",
        r"ws2_32\.dll:(?:connect|socket|WSASocket[AW]?)\b", r"\bnet\.(?:connect|createConnection)\s*\(",
        r"\bnew\s+net\.Socket\b")),
    # ── Exfiltration ──
    Rule("T1041", "Exfiltration Over C2 Channel", "Exfiltration", 15, _p(
        r"requests\.post\s*\(", r"\bcurl\b[^\n|]*\s(?:-d|--data(?:-binary)?|-F|-T)\s",
        r"Invoke-RestMethod\b.*-Method\s+Post", r"method\s*:\s*['\"]POST['\"]")),
    # ── Impact ──
    Rule("T1496", "Resource Hijacking", "Impact", 20, _p(r"xmrig", r"stratum\+tcp", r"\bminerd\b", r"cryptonight")),
    Rule("T1490", "Inhibit System Recovery", "Impact", 30, _p(
        r"vssadmin\s+delete\s+shadows", r"wbadmin\s+delete", r"bcdedit.*recoveryenabled")),
)


# ─── Analyst ─────────────────────────────────────────────────

def _provenance_explanation(provenance: Dict[str, Any]) -> str:
    attribution = attribution_from_provenance(provenance)
    match = str(provenance.get("ecosystem_match") or "None")
    injected = [str(item) for item in (provenance.get("injected_artifacts") or [])]

    if attribution.suspected_package:
        sample = ", ".join(_clip(item, 60) for item in injected[:3])
        delta = (
            f" {len(injected)} artifact(s) fall outside that library's known baseline and are treated "
            f"as the injected delta: {sample}." if injected else " No artifacts fall outside its known baseline."
        )
        return f"The extracted features most closely resemble {match}.{delta}"
    if attribution.ecosystem == "Native/Unknown":
        return (
            f"No known open-source library baseline matched ({match}); all {len(injected)} extracted "
            "artifact(s) are treated as native to this sample."
        )
    return "No provenance signal: the sample exposed no strings or imports to compare against library baselines."


def analyze_features(features: Dict[str, Any]) -> AnalystReport:
    """Map an ExtractionResult to ATT&CK techniques using the rule table."""
    view = IndicatorView.from_features(features)

    fired: List[Tuple[Rule, str]] = []
    for rule in RULES:
        evidence = rule.evaluate(view)
        if evidence:
            fired.append((rule, evidence))

    fired.sort(key=lambda item: (TACTIC_ORDER.index(item[0].tactic), -item[0].weight))
    score = min(100, sum(rule.weight for rule, _ in fired))
    kind = view.file_type + (f"/{view.language}" if view.language not in ("", "unknown") else "")

    if fired:
        tactics = _unique(rule.tactic for rule, _ in fired)
        top = [rule.name for rule, _ in sorted(fired, key=lambda item: -item[0].weight)[:4]]
        summary = (
            f"Heuristic (offline) assessment of {view.filename} ({kind}): matched {len(fired)} MITRE ATT&CK "
            f"technique(s) across {', '.join(tactics)}. Most significant behaviours: {'; '.join(top)}."
        )
        network = [s for s in view.strings if URL_RE.match(s) or IPV4_RE.fullmatch(s)]
        if network:
            summary += f" Network indicators: {', '.join(_clip(item, 60) for item in network[:3])}."
    else:
        summary = (
            f"Heuristic (offline) assessment of {view.filename} ({kind}): no known-malicious indicators "
            "matched the rule set. This is not a clean bill of health — rule coverage is limited and no "
            "code was executed."
        )

    return AnalystReport(
        behavioral_summary=summary,
        threat_level=level_from_score(score),
        threat_score=score,
        mitre_mapping=[
            MitreTechnique(tactic=rule.tactic, technique_id=rule.technique_id,
                           technique_name=rule.name, evidence=evidence)
            for rule, evidence in fired
        ],
        provenance_explanation=_provenance_explanation(view.provenance),
        attribution=attribution_from_provenance(view.provenance),
        engine=ENGINE_NAME,
    )


class HeuristicAnalystAgent:
    """Rule-based analyst with the same interface as the Gemini analyst."""

    async def analyze(self, malware_context: Dict[str, Any]) -> AnalystReport:
        return analyze_features(malware_context)


# ─── Detection engineering ───────────────────────────────────

def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _is_strong_indicator(value: str) -> bool:
    """URLs, registry keys and Windows paths are specific enough to match alone."""
    return bool(URL_RE.search(value) or REGISTRY_RE.search(value) or WINDOWS_PATH_RE.search(value))


def _is_weak_indicator(value: str) -> bool:
    """IPs and Unix paths are only meaningful in combination."""
    return bool(IPV4_RE.search(value) or UNIX_PATH_RE.search(value))


def _yara_escape(value: str) -> str:
    """Escape a value for use inside a YARA text string."""
    out: List[str] = []
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif 32 <= code < 127:
            out.append(ch)
        else:
            out.extend(f"\\x{byte:02x}" for byte in ch.encode("utf-8"))
    return "".join(out)


def _yara_rule_name(filename: str, sha256: str) -> str:
    stem = os.path.splitext(os.path.basename(filename.replace("\\", "/")))[0]
    stem = re.sub(r"[^A-Za-z0-9]+", "_", stem).strip("_")[:40] or "sample"
    return f"OriginTrace_{stem}_{(sha256 or 'unknown')[:8]}"


def build_yara_rule(filename: str, sha256: str, file_type: str, size: int,
                    indicators: Sequence[str], legitimate_baseline: Sequence[str],
                    threat_level: str, encoded_blobs: Sequence[str] = ()) -> str:
    """
    Build a YARA rule from extracted indicators.

    Strings from the legitimate library baseline are never used. With no
    usable indicator the rule pins the exact file by hash instead, so the
    output is always valid YARA.
    """
    baseline = set(legitimate_baseline)
    strong: List[str] = []
    weak: List[str] = []
    for value in _unique(indicators):
        if value in baseline or len(value) < MIN_YARA_STRING_CHARS:
            continue
        value = value[:MAX_YARA_STRING_CHARS]
        if _is_strong_indicator(value) and len(strong) < MAX_STRONG_STRINGS:
            strong.append(value)
        elif _is_weak_indicator(value) and len(weak) < MAX_WEAK_STRINGS:
            weak.append(value)
    blobs = [blob[:BLOB_PREFIX_CHARS] for blob in _unique(encoded_blobs)[:MAX_BLOB_STRINGS]
             if len(blob) >= BLOB_PREFIX_CHARS]
    weak_all = weak + blobs
    # YARA rejects unreferenced strings, so a lone weak string is only kept
    # when it is the whole condition.
    if strong and len(weak_all) == 1:
        weak, blobs, weak_all = [], [], []

    name = _yara_rule_name(filename, sha256)
    meta = [
        f'description = "Detects artifacts extracted from {_yara_escape(_clip(filename, 80))}"',
        'author = "OriginTrace heuristic engine"',
        f'date = "{_today()}"',
        f'hash = "{sha256 or "unknown"}"',
        f'threat_level = "{_yara_escape(threat_level)}"',
    ]
    meta_block = "\n".join(f"        {line}" for line in meta)

    if not strong and not weak_all:
        condition = (
            f'filesize == {int(size or 0)} and hash.sha256(0, filesize) == "{sha256}"'
            if sha256 else "false"
        )
        return (
            'import "hash"\n\n'
            f"rule {name}\n{{\n    meta:\n{meta_block}\n    condition:\n        {condition}\n}}\n"
        )

    string_lines = [f'        $s{i} = "{_yara_escape(value)}" ascii wide' for i, value in enumerate(strong)]
    string_lines += [f'        $w{i} = "{_yara_escape(value)}" ascii wide' for i, value in enumerate(weak_all)]

    clauses = []
    if strong:
        clauses.append("any of ($s*)")
    if len(weak_all) >= 2:
        clauses.append("2 of ($w*)")
    elif weak_all:
        clauses.append("all of ($w*)")
    match_clause = clauses[0] if len(clauses) == 1 else f"({' or '.join(clauses)})"

    guards = []
    if file_type == "pe":
        guards.append("uint16(0) == 0x5A4D")
    elif file_type == "elf":
        guards.append("uint32(0) == 0x464C457F")
    guards.append(f"filesize < {max(int(size or 0) * 4, 1024 * 1024)}")
    condition = " and ".join(guards + [match_clause])

    strings_block = "\n".join(string_lines)
    return (
        f"rule {name}\n{{\n    meta:\n{meta_block}\n    strings:\n{strings_block}\n"
        f"    condition:\n        {condition}\n}}\n"
    )


def _sigma_quote(value: str) -> str:
    """Single-quote a scalar for YAML; control characters become spaces."""
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value))
    return "'" + cleaned.replace("'", "''") + "'"


def _sigma_product(file_type: str, language: str, indicators: Sequence[str]) -> str:
    if file_type in ("pe", "document") or language in ("powershell", "batch"):
        return "windows"
    if file_type == "elf" or language == "shell":
        return "linux"
    if any(WINDOWS_PATH_RE.search(i) or REGISTRY_RE.search(i) for i in indicators):
        return "windows"
    if any(UNIX_PATH_RE.search(i) for i in indicators):
        return "linux"
    return "windows"


def build_sigma_rule(filename: str, sha256: str, file_type: str, language: str,
                     indicators: Sequence[str], mitre_mapping: Sequence[Dict[str, Any]],
                     threat_level: str) -> str:
    """Build a process-creation Sigma rule from command-line indicators."""
    values = _unique(indicators)[:MAX_SIGMA_INDICATORS]
    product = _sigma_product(file_type, language, values)

    tags: List[str] = []
    for technique in mitre_mapping:
        tactic = str(technique.get("tactic") or "").strip().lower().replace(" ", "_")
        technique_id = str(technique.get("technique_id") or "").strip().lower()
        if tactic:
            tags.append(f"attack.{tactic}")
        if technique_id:
            tags.append(f"attack.{technique_id}")
    tags = _unique(tags)

    lines = [
        f"title: {_sigma_quote('OriginTrace - Suspicious activity linked to ' + _clip(filename, 80))}",
        f"id: {uuid.uuid5(uuid.NAMESPACE_URL, 'origintrace:' + (sha256 or filename))}",
        "status: experimental",
        f"description: {_sigma_quote('Command lines referencing indicators extracted from ' + _clip(filename, 80) + ' (SHA256 ' + (sha256 or 'unknown') + ').')}",
        "author: OriginTrace heuristic engine",
        f"date: {_today()}",
    ]
    if tags:
        lines.append("tags:")
        lines += [f"    - {tag}" for tag in tags]
    lines += [
        "logsource:",
        "    category: process_creation",
        f"    product: {product}",
        "detection:",
        "    selection:",
    ]
    if values:
        lines.append("        CommandLine|contains:")
        lines += [f"            - {_sigma_quote(value)}" for value in values]
    else:
        lines.append(f"        Hashes|contains: {_sigma_quote('SHA256=' + (sha256 or '').upper())}")
    lines += [
        "    condition: selection",
        "falsepositives:",
        "    - Legitimate administration or deployment scripts using the same commands",
        f"level: {str(threat_level or 'low').lower()}",
    ]
    return "\n".join(lines) + "\n"


def _sigma_indicators(candidates: Sequence[str], baseline: Sequence[str]) -> List[str]:
    """Rank indicators for a command line: URLs, then IPs, then paths."""
    excluded = set(baseline)
    usable = [c for c in _unique(candidates) if c not in excluded]
    urls = [c for c in usable if URL_RE.match(c)]
    ips = [c for c in usable if IPV4_RE.fullmatch(c)]
    paths = [c for c in usable if c not in urls and c not in ips
             and (UNIX_PATH_RE.search(c) or WINDOWS_PATH_RE.search(c) or REGISTRY_RE.search(c))]
    return (urls + ips + paths)[:MAX_SIGMA_INDICATORS]


class HeuristicDetectionEngineerAgent:
    """Rule generator with the same interface as the Gemini detection engineer."""

    async def generate_rules(self, malware_context: Dict[str, Any],
                             analyst_report: Dict[str, Any]) -> DetectionArtifacts:
        features = malware_context or {}
        report = analyst_report or {}
        view = IndicatorView.from_features(features)
        metadata = features.get("metadata") or {}
        provenance = view.provenance

        injected = [str(item) for item in (provenance.get("injected_artifacts") or [])]
        baseline = [str(item) for item in (provenance.get("legitimate_baseline") or [])]
        candidates = _unique(injected + view.strings)
        sha256 = str(metadata.get("sha256") or "")
        threat_level = str(report.get("threat_level") or "Low")

        yara_rule = build_yara_rule(
            filename=view.filename,
            sha256=sha256,
            file_type=view.file_type,
            size=int(metadata.get("size") or 0),
            indicators=candidates,
            legitimate_baseline=baseline,
            threat_level=threat_level,
            encoded_blobs=view.blobs,
        )
        sigma_rule = build_sigma_rule(
            filename=view.filename,
            sha256=sha256,
            file_type=view.file_type,
            language=view.language,
            indicators=_sigma_indicators(candidates, baseline),
            mitre_mapping=report.get("mitre_mapping") or [],
            threat_level=threat_level,
        )
        return DetectionArtifacts(yara_rule=yara_rule, sigma_rule=sigma_rule, engine=ENGINE_NAME)
