"""
OriginTrace — Helpers shared by the analysis agents

Keeps the Gemini agents and the offline heuristic agents consistent about
how extraction output is trimmed, how severity is expressed, and how the
provenance result is turned into a supply-chain attribution.
"""
import copy
import re
from typing import Any, Dict

from models import Attribution

# Caps applied before features are sent to an LLM. Symbol-heavy binaries
# would otherwise blow the context window (and the bill).
MAX_IMPORTS = 200
MAX_SYMBOLS = 200
MAX_STRINGS = 150
MAX_ARTIFACTS = 150
MAX_FUNCTIONS = 8
MAX_DECOMPILED_CHARS = 4000
MAX_ARCHIVE_MEMBERS = 15
MAX_MEMBER_EXCERPT_CHARS = 800

HIGH_THRESHOLD = 65
MEDIUM_THRESHOLD = 30

_LEVEL_SCORES = {"High": 85, "Medium": 50, "Low": 15}
_TRAILING_PARENTHETICAL_RE = re.compile(r"\s*\([^()]*\)\s*$")
_NO_ATTRIBUTION = {"", "none", "unknown", "unavailable"}


def level_from_score(score: int) -> str:
    """Map a 0-100 threat score onto High / Medium / Low."""
    if score >= HIGH_THRESHOLD:
        return "High"
    if score >= MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def normalize_threat_level(value: str, score: int = 0) -> str:
    """Coerce free-form severity text ("high", "CRITICAL") to the contract."""
    text = (value or "").strip().lower()
    if text in ("high", "critical", "severe"):
        return "High"
    if text in ("medium", "moderate", "med"):
        return "Medium"
    if text in ("low", "informational", "info", "benign", "none"):
        return "Low"
    return level_from_score(score)


def score_from_level(level: str) -> int:
    """Representative score for a severity level when none was supplied."""
    return _LEVEL_SCORES.get(level, 15)


def attribution_from_provenance(provenance: Dict[str, Any]) -> Attribution:
    """
    Turn a provenance `ecosystem_match` string into a structured attribution.

    "PyPI: requests-v2 (87% similarity)" -> ecosystem "PyPI", package "requests-v2"
    "Native/Unknown (Best match: 12%)"   -> ecosystem "Native/Unknown"
    """
    match = str((provenance or {}).get("ecosystem_match") or "")
    body = _TRAILING_PARENTHETICAL_RE.sub("", match).strip()
    if body.lower() in _NO_ATTRIBUTION:
        return Attribution(ecosystem="Unknown", suspected_package=None)
    if ":" in body:
        ecosystem, package = body.split(":", 1)
        return Attribution(ecosystem=ecosystem.strip(), suspected_package=package.strip() or None)
    return Attribution(ecosystem=body, suspected_package=None)


def build_llm_context(features: Dict[str, Any]) -> Dict[str, Any]:
    """Return a size-bounded deep copy of the extraction result for an LLM prompt."""
    context = copy.deepcopy(features or {})

    binary = context.get("binary_features")
    if isinstance(binary, dict):
        for key, cap in (("imports", MAX_IMPORTS), ("elf_symbols", MAX_SYMBOLS), ("high_value_strings", MAX_STRINGS)):
            if isinstance(binary.get(key), list):
                binary[key] = binary[key][:cap]
        functions = binary.get("functions")
        if isinstance(functions, list):
            binary["functions"] = functions[:MAX_FUNCTIONS]
            for function in binary["functions"]:
                code = function.get("decompiled_c") if isinstance(function, dict) else None
                if isinstance(code, str) and len(code) > MAX_DECOMPILED_CHARS:
                    function["decompiled_c"] = code[:MAX_DECOMPILED_CHARS] + "\n// [TRUNCATED]"

    for section in ("script_features", "document_features", "archive_features"):
        payload = context.get(section)
        if isinstance(payload, dict) and isinstance(payload.get("high_value_strings"), list):
            payload["high_value_strings"] = payload["high_value_strings"][:MAX_STRINGS]

    archive = context.get("archive_features")
    if isinstance(archive, dict):
        for key in ("imports", "suspicious_calls"):
            if isinstance(archive.get(key), list):
                archive[key] = archive[key][:MAX_STRINGS]
        members = archive.get("analyzed_members")
        if isinstance(members, list):
            archive["analyzed_members"] = members[:MAX_ARCHIVE_MEMBERS]
            for member in archive["analyzed_members"]:
                excerpt = member.get("source_excerpt") if isinstance(member, dict) else None
                if isinstance(excerpt, str):
                    member["source_excerpt"] = excerpt[:MAX_MEMBER_EXCERPT_CHARS]

    provenance = context.get("provenance")
    if isinstance(provenance, dict) and isinstance(provenance.get("injected_artifacts"), list):
        provenance["injected_artifacts"] = provenance["injected_artifacts"][:MAX_ARTIFACTS]

    return context
