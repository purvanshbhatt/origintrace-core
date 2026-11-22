"""
OriginTrace — Mock Agents (demo mode)

Canned pipeline stages for UI demos and frontend development. They emit the
same `FinalReport` contract as the real pipeline, so the frontend needs no
mock-specific code. Only the file hashes and size are real; every finding is
fixed demo data and is labelled as such.
"""
import asyncio
import hashlib
import os
import time
from typing import Any, Dict, Optional

from models import AnalystReport, Attribution, DetectionArtifacts, MitreTechnique

ENGINE_NAME = "mock"
DEFAULT_DELAY_S = 1.0
_HASH_CHUNK_BYTES = 1024 * 1024

_DEMO_IMPORTS = ["kernel32.dll:CreateFileA", "ws2_32.dll:socket"]
_DEMO_STRINGS = ["http://malicious.c2/drop", "npm install hidden-miner"]


def _default_delay() -> float:
    """Simulated per-stage latency, overridable with MOCK_DELAY_S."""
    try:
        return max(0.0, float(os.environ.get("MOCK_DELAY_S", DEFAULT_DELAY_S)))
    except ValueError:
        return DEFAULT_DELAY_S


class BinaryExtractor:
    def __init__(self, delay: Optional[float] = None):
        self.delay = _default_delay() if delay is None else delay

    def extract_all(self, file_path: str, filename: str) -> Dict[str, Any]:
        """Hash the real upload, then return fixed demo features."""
        sha256, md5, size = hashlib.sha256(), hashlib.md5(), 0
        with open(file_path, "rb") as f:
            while chunk := f.read(_HASH_CHUNK_BYTES):
                sha256.update(chunk)
                md5.update(chunk)
                size += len(chunk)

        # Simulate local parsing time
        time.sleep(self.delay)
        return {
            "metadata": {
                "filename": filename,
                "sha256": sha256.hexdigest(),
                "md5": md5.hexdigest(),
                "size": size,
                "file_type": "pe",
                "extension_mismatch": False,
            },
            "file_type": "pe",
            "binary_features": {
                "imports": list(_DEMO_IMPORTS),
                "sections": [".text (Entropy: 6.41)", ".rsrc (Entropy: 7.62)"],
                "functions": [],
                "high_value_strings": list(_DEMO_STRINGS),
                "imphash": "b86de0f594511d73c71ea40aa8c12a76",
            },
            "script_features": None,
            "document_features": None,
            "provenance": {
                "ecosystem_match": "NPM: colors-js-hijack (demo data)",
                "legitimate_baseline": ["const colors = require('colors')"],
                "injected_artifacts": list(_DEMO_STRINGS),
                "engine": ENGINE_NAME,
            },
            "status": "success (mock data)",
        }


class ThreatAnalystAgent:
    def __init__(self, delay: Optional[float] = None):
        self.delay = _default_delay() if delay is None else delay

    async def analyze(self, malware_context: Dict[str, Any]) -> AnalystReport:
        # Simulate LLM thinking time
        await asyncio.sleep(self.delay)
        return AnalystReport(
            behavioral_summary="[DEMO DATA] Binary acts as a dropper, suspected to originate from a compromised npm package and executes a reverse shell.",
            threat_level="High",
            threat_score=88,
            mitre_mapping=[
                MitreTechnique(
                    tactic="Execution",
                    technique_id="T1059.004",
                    technique_name="Unix Shell",
                    evidence="Command and Scripting Interpreter: Unix Shell. String found 'npm install hidden-miner'"
                ),
                MitreTechnique(
                    tactic="Command and Control",
                    technique_id="T1071.001",
                    technique_name="Application Layer Protocol: Web Protocols",
                    evidence="Application Layer Protocol: Web Protocols. Imports ws2_32.dll and strings indicate HTTP C2."
                )
            ],
            provenance_explanation="[DEMO DATA] The sample resembles the npm package colors-js with an injected installer and C2 URL.",
            attribution=Attribution(
                ecosystem="npm",
                suspected_package="colors-js-hijack"
            ),
            engine=ENGINE_NAME,
        )


class DetectionEngineerAgent:
    def __init__(self, delay: Optional[float] = None):
        self.delay = _default_delay() if delay is None else delay

    async def generate_rules(self, malware_context: Dict[str, Any],
                             analyst_report: Dict[str, Any]) -> DetectionArtifacts:
        # Simulate LLM thinking time
        await asyncio.sleep(self.delay)
        yara_rule = """rule NPM_ReverseShell_Dropper {
    meta:
        description = "Detects NPM hijacked dropper (demo data)"
        author = "OriginTrace"
    strings:
        $c2 = "http://malicious.c2/drop"
        $cmd = "npm install hidden-miner"
    condition:
        uint16(0) == 0x5a4d and all of them
}"""
        sigma_rule = """title: Suspicious NPM Hidden Miner Installation
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'npm install hidden-miner'
    condition: selection
"""
        return DetectionArtifacts(
            yara_rule=yara_rule,
            sigma_rule=sigma_rule,
            engine=ENGINE_NAME,
        )
