from pydantic import BaseModel, Field
from typing import List, Optional

class MitreTechnique(BaseModel):
    tactic: str = Field(description="The MITRE ATT&CK Tactic (e.g., Execution, Defense Evasion)")
    technique_id: str = Field(description="The specific MITRE ATT&CK Technique ID (e.g., T1059)")
    ai_evidence: str = Field(description="Explanation of why this technique was flagged by the analysis.")

class AnalysisResult(BaseModel):
    behavioral_summary: str = Field(description="A concise DFIR summary of the file's intent and capabilities.")
    mitre_ttps: List[MitreTechnique] = Field(description="List of mapped MITRE ATT&CK techniques with evidence.")
    yara_rule: str = Field(description="A complete, valid YARA rule string targeting the specific malicious payload/injected artifacts.")
    sigma_rule: str = Field(description="A complete, valid Sigma rule characterizing the behavioral execution trace.")
    threat_score: int = Field(description="Integer from 0 to 100 assessing the severity of the analyzed file.", ge=0, le=100)
    
class FinalAnalysis(BaseModel):
    features: dict = Field(description="Raw features extracted from the binary")
    intelligence: AnalysisResult = Field(description="Structured AI analysis from the IntelligenceAgent")
