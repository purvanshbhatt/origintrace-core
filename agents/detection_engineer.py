import json
from pydantic import BaseModel
from google import genai
from google.genai import types

class DetectionArtifacts(BaseModel):
    yara_rule: str
    sigma_rule: str

class DetectionEngineerAgent:
    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)
        self.model_id = "gemini-2.0-flash"

    def _get_system_prompt(self) -> str:
        return """
**ROLE**
You are the OriginTrace Detection Engineer. You are receiving raw malware features and a Threat Analyst's report. 

**CRITICAL REQUIREMENT**
You will see a list of `legitimate_baseline` strings/imports in the malware context. YOU MUST EXCLUDE THESE FROM YOUR RULES. They belong to legitimate libraries (like boto3 or React). You must ONLY target the `injected_artifacts` and behavioral TTPs to ensure a 0% False Positive rate.

**TASKS**
Generate ONE highly specific, production-grade YARA rule (static) and ONE Sigma rule (behavioral) that act explicitly on the malicious delta identified. Guarantee that safe operations are ignored.

Provide raw, valid YARA syntax and raw, valid Sigma YAML syntax.
"""

    async def generate_rules(self, malware_context: dict, analyst_report: dict) -> DetectionArtifacts:
        """
        Asynchronously generates YARA and Sigma rules via Gemini 2.0 Flash, targeting only injected artifacts
        and explicitly avoiding legitimate supply chain baselines.
        """
        prompt = f"""
# MALWARE CONTEXT (Raw Extraction & Provenance)
{json.dumps(malware_context)}

# THREAT ANALYST REPORT (TTPs & Ecosystem)
{json.dumps(analyst_report)}
"""
        
        # Enforce structured output using the Pydantic schema
        config = types.GenerateContentConfig(
            system_instruction=self._get_system_prompt(),
            response_mime_type="application/json",
            response_schema=DetectionArtifacts,
            temperature=0.0,
        )

        # google-genai structured generation natively supports async calls
        response = await self.client.aio.models.generate_content(
            model=self.model_id,
            contents=prompt,
            config=config
        )

        # The SDK automatically handles the JSON parsing given a response_schema,
        # but to ensure perfect typing, we load it into our Pydantic model.
        return DetectionArtifacts.model_validate_json(response.text)
