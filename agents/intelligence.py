from google import genai
from google.genai import types
import json


class MasterIntelligenceAgent:
    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)
        self.model_id = "gemini-2.0-flash"

    def _get_system_prompt(self) -> str:
        return """
**ROLE**
You are the OriginTrace Master Intelligence Agent. Provide high-fidelity malware analysis and supply chain attribution.

**TASKS**
1. Analyze behaviors and map them to MITRE ATT&CK techniques with evidence based on the imports and strings.
2. Perform "Semantic Provenance Analysis": Determine if this binary is a hijacked version of a legitimate library (pip/npm) or native malware.
3. Generate ONE production-grade YARA rule (static) and ONE Sigma rule (behavioral).

**CRITICAL RULE**
When generating rules, EXCLUDE Legitimate Baseline strings. Target ONLY the Injected Malicious Artifacts to ensure 0% False Positive rate on goodware.

**OUTPUT SCHEMA**
You must return ONLY a valid JSON object matching exactly this schema:
{
  "summary": { "behavior": "string", "threat_level": "High|Medium|Low" },
  "mitre_mapping": [ { "technique_id": "TXXXX", "technique_name": "string", "evidence": "string" } ],
  "attribution": { "origin": "npm|pip|native", "suspected_package": "string|null" },
  "detections": { "yara_rule": "string", "sigma_rule": "string" }
}
"""

    def analyze(self, local_features: dict) -> dict:
        prompt = f"RAW INPUT DATA (Local Features):\n{json.dumps(local_features)}"

        response = self.client.models.generate_content(
            model=self.model_id,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=self._get_system_prompt(),
                response_mime_type="application/json",
                temperature=0.1,  # Low temp for deterministic analysis
            ),
        )

        return json.loads(response.text)
