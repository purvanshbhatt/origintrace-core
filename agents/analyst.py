"""
OriginTrace — Threat Analyst Agent (Gemini)

Translates raw extraction features into a MITRE ATT&CK report and explains
the supply-chain delta found by the provenance engine.
"""
import json
from typing import Any, List, Optional

from pydantic import BaseModel, Field

from agents.context import (
    attribution_from_provenance,
    build_llm_context,
    normalize_threat_level,
)
from agents.llm import (
    UNTRUSTED_DATA_NOTICE,
    default_model,
    default_timeout,
    fence_untrusted,
    generate_structured,
    make_client,
)
from models import AnalystReport, Attribution, MitreTechnique

ENGINE_NAME = "gemini"


# --- STRICT SCHEMA FOR AGENT 1 ---
# Every field is required and default-free: Gemini's structured output does
# not accept defaults. The API-facing models live in models.py.
class LLMMitreTechnique(BaseModel):
    tactic: str = Field(description="MITRE Tactic (e.g., Execution, Defense Evasion)")
    technique_id: str = Field(description="e.g., T1059.006")
    technique_name: str = Field(description="Official technique name, e.g., Python")
    evidence: str = Field(description="Explanation citing specific context features")


class LLMAnalystReport(BaseModel):
    behavioral_summary: str = Field(description="DFIR-grade summary of what the sample does")
    threat_level: str = Field(description="High, Medium, or Low")
    threat_score: int = Field(description="Severity from 0 (benign) to 100 (critical)")
    mitre_mapping: List[LLMMitreTechnique]
    provenance_explanation: str = Field(
        description="Human-readable explanation of the supply chain attack, interpreting ecosystem_match and injected_artifacts."
    )
    suspected_ecosystem: str = Field(description="Package ecosystem the sample hijacks (PyPI, NPM, ...); empty if none")
    suspected_package: str = Field(description="Hijacked package name; empty if none")


SYSTEM_PROMPT = """You are the OriginTrace Threat Analyst.
You are receiving a `MalwareContext` containing static features of a file (PE/ELF imports and decompiled C-pseudocode, script source and suspicious calls, or Office macro source), plus deterministic provenance results from a library-baseline search.
Your job is to translate these raw features into a strategic MITRE ATT&CK report and explain the supply chain delta.
Ground every technique in a feature that is actually present in the context; do not speculate beyond the evidence.
"""


class ThreatAnalystAgent:
    def __init__(self, api_key: str, *, client: Optional[Any] = None,
                 model_id: Optional[str] = None, timeout_s: Optional[float] = None):
        self.client = client if client is not None else make_client(api_key)
        self.model_id = model_id or default_model()
        self.timeout_s = timeout_s if timeout_s is not None else default_timeout()
        self.system_prompt = f"{SYSTEM_PROMPT}\n{UNTRUSTED_DATA_NOTICE}"

    async def analyze(self, malware_context: dict) -> AnalystReport:
        """
        Produce the analyst report for an extraction result.

        Raises:
            LLMResponseError: when Gemini times out or returns unusable output.
        """
        context = build_llm_context(malware_context)
        prompt = (
            "Analyse the MalwareContext below and produce the report.\n\n"
            + fence_untrusted("MALWARE CONTEXT", json.dumps(context, indent=2, default=str))
        )

        raw = await generate_structured(
            self.client,
            model_id=self.model_id,
            system_instruction=self.system_prompt,
            prompt=prompt,
            schema=LLMAnalystReport,
            timeout_s=self.timeout_s,
        )

        score = max(0, min(100, int(raw.threat_score)))
        ecosystem = raw.suspected_ecosystem.strip()
        if ecosystem:
            attribution = Attribution(ecosystem=ecosystem, suspected_package=raw.suspected_package.strip() or None)
        else:
            # No LLM opinion: fall back to the deterministic provenance result.
            attribution = attribution_from_provenance((malware_context or {}).get("provenance") or {})

        return AnalystReport(
            behavioral_summary=raw.behavioral_summary,
            threat_level=normalize_threat_level(raw.threat_level, score),
            threat_score=score,
            mitre_mapping=[MitreTechnique(**technique.model_dump()) for technique in raw.mitre_mapping],
            provenance_explanation=raw.provenance_explanation,
            attribution=attribution,
            engine=ENGINE_NAME,
        )
