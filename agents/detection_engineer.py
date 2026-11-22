"""
OriginTrace — Detection Engineer Agent (Gemini)

Generates one YARA rule (static) and one Sigma rule (behavioural) that
target only the injected delta, never the legitimate library baseline.
"""
import json
import re
from typing import Any, Optional

from pydantic import BaseModel, Field

from agents.context import build_llm_context
from agents.llm import (
    UNTRUSTED_DATA_NOTICE,
    LLMResponseError,
    default_model,
    default_timeout,
    fence_untrusted,
    generate_structured,
    make_client,
)
from models import DetectionArtifacts

ENGINE_NAME = "gemini"

_CODE_FENCE_RE = re.compile(r"^\s*```[\w-]*\s*\n(.*?)\n?```\s*$", re.DOTALL)


class LLMDetectionArtifacts(BaseModel):
    yara_rule: str = Field(description="Raw, valid YARA rule text (no markdown)")
    sigma_rule: str = Field(description="Raw, valid Sigma rule YAML (no markdown)")


def _strip_code_fence(text: str) -> str:
    """Remove a markdown code fence if the model wrapped its output in one."""
    match = _CODE_FENCE_RE.match(text or "")
    return (match.group(1) if match else (text or "")).strip()


class DetectionEngineerAgent:
    def __init__(self, api_key: str, *, client: Optional[Any] = None,
                 model_id: Optional[str] = None, timeout_s: Optional[float] = None):
        self.client = client if client is not None else make_client(api_key)
        self.model_id = model_id or default_model()
        self.timeout_s = timeout_s if timeout_s is not None else default_timeout()

    def _get_system_prompt(self) -> str:
        return f"""
**ROLE**
You are the OriginTrace Detection Engineer. You are receiving raw malware features and a Threat Analyst's report.

**CRITICAL REQUIREMENT**
You will see a list of `legitimate_baseline` strings/imports in the malware context. YOU MUST EXCLUDE THESE FROM YOUR RULES. They belong to legitimate libraries (like boto3 or React). You must ONLY target the `injected_artifacts` and behavioral TTPs to ensure a 0% False Positive rate.

**TASKS**
Generate ONE highly specific, production-grade YARA rule (static) and ONE Sigma rule (behavioral) that act explicitly on the malicious delta identified. Guarantee that safe operations are ignored.

Provide raw, valid YARA syntax and raw, valid Sigma YAML syntax.

{UNTRUSTED_DATA_NOTICE}
"""

    async def generate_rules(self, malware_context: dict, analyst_report: dict) -> DetectionArtifacts:
        """
        Asynchronously generates YARA and Sigma rules via Gemini, targeting only injected artifacts
        and explicitly avoiding legitimate supply chain baselines.

        Raises:
            LLMResponseError: when Gemini times out or returns unusable rules.
        """
        context = build_llm_context(malware_context)
        prompt = "\n\n".join([
            "Write the detection rules for the sample described below.",
            fence_untrusted("MALWARE CONTEXT (Raw Extraction & Provenance)", json.dumps(context, default=str)),
            fence_untrusted("THREAT ANALYST REPORT (TTPs & Ecosystem)", json.dumps(analyst_report, default=str)),
        ])

        raw = await generate_structured(
            self.client,
            model_id=self.model_id,
            system_instruction=self._get_system_prompt(),
            prompt=prompt,
            schema=LLMDetectionArtifacts,
            timeout_s=self.timeout_s,
        )

        yara_rule = _strip_code_fence(raw.yara_rule)
        sigma_rule = _strip_code_fence(raw.sigma_rule)
        if "rule" not in yara_rule or "condition" not in yara_rule:
            raise LLMResponseError("Gemini returned a YARA rule without a rule/condition block")
        if not sigma_rule:
            raise LLMResponseError("Gemini returned an empty Sigma rule")

        return DetectionArtifacts(yara_rule=yara_rule, sigma_rule=sigma_rule, engine=ENGINE_NAME)
