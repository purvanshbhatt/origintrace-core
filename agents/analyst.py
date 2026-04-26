import json
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from typing import List

# --- STRICT SCHEMA FOR AGENT 1 ---
class MitreTechnique(BaseModel):
    tactic: str = Field(description="MITRE Tactic (e.g., Execution, Defense Evasion)")
    technique_id: str = Field(description="e.g., T1059")
    evidence: str = Field(description="Explanation based on context features")

class AnalystReport(BaseModel):
    behavioral_summary: str = Field(description="DFIR-grade summary of what the malware does")
    threat_level: str = Field(description="High, Medium, or Low")
    mitre_mapping: List[MitreTechnique]
    provenance_explanation: str = Field(
        description="Human-readable explanation of the supply chain attack, interpreting FAISS ecosystem_match and injected_artifacts."
    )

class ThreatAnalystAgent:
    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)
        self.model_id = 'gemini-2.0-flash'
        
        self.system_prompt = """You are the OriginTrace Threat Analyst. 
You are receiving a `MalwareContext` containing static PE features, r2pipe entrypoint disassembly, and deterministic FAISS vector search results (Provenance). 
Your job is to translate these raw features into a strategic MITRE ATT&CK report and explain the supply chain delta.
"""

    async def analyze(self, malware_context: dict) -> AnalystReport:
        prompt = f"{self.system_prompt}\n\nMALWARE CONTEXT:\n{json.dumps(malware_context, indent=2)}"
        
        # Enforcing Pydantic Schema via the new GenAI SDK synchronously inside an async wrapper,
        # or utilizing the genai client's async generation if supported natively.
        # Since google-genai supports async, we use aio:
        response = await self.client.aio.models.generate_content(
            model=self.model_id,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=AnalystReport,
                temperature=0.1
            )
        )
        
        # Return the parsed Pydantic object
        return AnalystReport.model_validate_json(response.text)
