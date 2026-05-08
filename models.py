"""
OriginTrace — Unified Data Models

Polymorphic schema design supporting PE, ELF, Script, and Document extraction.
Each file type populates its own feature set; the LLM receives a normalized
ExtractionResult regardless of the input format.
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


# ─── MITRE ATT&CK ───────────────────────────────────────────
class MitreTechnique(BaseModel):
    tactic: str = Field(description="The MITRE ATT&CK Tactic (e.g., Execution, Defense Evasion)")
    technique_id: str = Field(description="The specific MITRE ATT&CK Technique ID (e.g., T1059)")
    ai_evidence: str = Field(description="Explanation of why this technique was flagged by the analysis.")


# ─── INTELLIGENCE OUTPUT ─────────────────────────────────────
class AnalysisResult(BaseModel):
    behavioral_summary: str = Field(description="A concise DFIR summary of the file's intent and capabilities.")
    mitre_ttps: List[MitreTechnique] = Field(description="List of mapped MITRE ATT&CK techniques with evidence.")
    yara_rule: str = Field(description="A complete, valid YARA rule string targeting the specific malicious payload/injected artifacts.")
    sigma_rule: str = Field(description="A complete, valid Sigma rule characterizing the behavioral execution trace.")
    threat_score: int = Field(description="Integer from 0 to 100 assessing the severity of the analyzed file.", ge=0, le=100)

class FinalAnalysis(BaseModel):
    features: dict = Field(description="Raw features extracted from the binary")
    intelligence: AnalysisResult = Field(description="Structured AI analysis from the IntelligenceAgent")


# ─── UNIVERSAL EXTRACTION FEATURES ──────────────────────────
# These sub-schemas are populated conditionally by each extractor.

class BinaryFeatures(BaseModel):
    """Features specific to compiled binaries (PE / ELF)."""
    imports: List[str] = Field(default_factory=list, description="IAT/dynamic symbol imports (e.g., kernel32.dll:VirtualAlloc)")
    sections: List[str] = Field(default_factory=list, description="Section names with entropy (e.g., .text (Entropy: 6.45))")
    functions: List[Dict[str, Any]] = Field(default_factory=list, description="Decompiled function records from r2ghidra")
    high_value_strings: List[str] = Field(default_factory=list, description="IOC-grade strings: URLs, registry keys, C2 domains")

    # PE-specific (optional — absent for ELF)
    imphash: Optional[str] = Field(default=None, description="PE import hash for clustering")

    # ELF-specific (optional — absent for PE)
    elf_type: Optional[str] = Field(default=None, description="ELF file type (EXEC, DYN, REL)")
    elf_machine: Optional[str] = Field(default=None, description="ELF target architecture (x86_64, ARM, MIPS)")
    elf_symbols: List[str] = Field(default_factory=list, description="Dynamic symbol table entries")


class ScriptFeatures(BaseModel):
    """Features extracted from interpreted scripts (Python, JavaScript, Shell)."""
    language: str = Field(description="Detected scripting language (python, javascript, shell, powershell)")
    raw_source: str = Field(description="Truncated raw source code (max 3000 chars for LLM context)")
    ast_imports: List[str] = Field(default_factory=list, description="Imported modules parsed from AST or regex")
    suspicious_calls: List[str] = Field(default_factory=list, description="Calls to eval(), exec(), subprocess, os.system, etc.")
    encoded_blobs: List[str] = Field(default_factory=list, description="Base64/hex-encoded payloads found in source")
    obfuscation_score: float = Field(default=0.0, description="Shannon entropy of the source as an obfuscation heuristic", ge=0.0, le=8.0)
    high_value_strings: List[str] = Field(default_factory=list, description="URLs, IPs, file paths, registry keys")


class DocumentFeatures(BaseModel):
    """Features extracted from weaponized Office documents (Word, Excel)."""
    doc_type: str = Field(description="Document format (OLE, OOXML)")
    has_macros: bool = Field(default=False, description="Whether VBA macros were detected")
    macro_source: Optional[str] = Field(default=None, description="Extracted VBA macro source code (truncated)")
    suspicious_keywords: List[str] = Field(default_factory=list, description="Keywords like AutoOpen, Shell, CreateObject, PowerShell")
    embedded_urls: List[str] = Field(default_factory=list, description="URLs extracted from macro code or document body")
    embedded_ole_objects: List[str] = Field(default_factory=list, description="Embedded OLE object names/types")
    high_value_strings: List[str] = Field(default_factory=list, description="IOC-grade strings from macro code")


class ExtractionResult(BaseModel):
    """
    Normalized root schema that the File Type Router produces.
    Exactly one of binary_features / script_features / document_features
    will be populated depending on the detected file type.
    """
    metadata: Dict[str, Any] = Field(description="File metadata: filename, sha256, md5, size, detected MIME type")
    file_type: str = Field(description="Canonical file class: pe, elf, script, document, unknown")

    # Polymorphic feature payloads — only one is populated per analysis
    binary_features: Optional[BinaryFeatures] = Field(default=None, description="Populated for PE and ELF files")
    script_features: Optional[ScriptFeatures] = Field(default=None, description="Populated for Python, JS, Shell scripts")
    document_features: Optional[DocumentFeatures] = Field(default=None, description="Populated for Office documents with macros")

    # Universal fields present regardless of file type
    provenance: Dict[str, Any] = Field(default_factory=lambda: {
        "ecosystem_match": "None",
        "legitimate_baseline": [],
        "injected_artifacts": []
    })
    status: str = Field(default="success")
