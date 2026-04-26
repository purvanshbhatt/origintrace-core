from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class MitreTechnique(BaseModel):
    tactic: str
    technique_id: str
    evidence: str

class Attribution(BaseModel):
    ecosystem: str
    suspected_package: Optional[str] = None

class AnalystReport(BaseModel):
    behavioral_summary: str
    threat_level: str
    mitre_mapping: List[MitreTechnique]
    attribution: Attribution

class DetectionArtifacts(BaseModel):
    yara_rule: str
    sigma_rule: str

class FinalReport(BaseModel):
    hashes: Dict[str, str]
    intelligence: AnalystReport
    detections: DetectionArtifacts
