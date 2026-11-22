"""
OriginTrace — Unified Data Models

Single source of truth for the API contract. Every analysis mode (Gemini,
offline heuristics, mock demo) produces a `FinalReport`, and the frontend
types in `frontend/src/types/report.ts` mirror these models.

Extraction is polymorphic: each file type populates its own feature set, and
the analysis agents receive a normalized `ExtractionResult` regardless of
the input format.
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"


# ─── INTELLIGENCE OUTPUT ─────────────────────────────────────
class MitreTechnique(BaseModel):
    """One MITRE ATT&CK technique mapped to evidence from the sample."""
    tactic: str = Field(description="The MITRE ATT&CK tactic (e.g., Execution, Defense Evasion)")
    technique_id: str = Field(description="The MITRE ATT&CK technique ID (e.g., T1059.006)")
    technique_name: str = Field(default="", description="Human-readable technique name")
    evidence: str = Field(description="Why this technique was flagged, citing extracted features")


class Attribution(BaseModel):
    """Supply-chain origin of the sample, when one can be inferred."""
    ecosystem: str = Field(default="Unknown", description="Package ecosystem (PyPI, NPM, Native/Unknown)")
    suspected_package: Optional[str] = Field(default=None, description="Library the sample appears to hijack")


class AnalystReport(BaseModel):
    """Threat assessment produced by the analyst stage."""
    behavioral_summary: str = Field(description="DFIR summary of the file's intent and capabilities")
    threat_level: str = Field(description="High, Medium, or Low")
    threat_score: int = Field(description="Severity from 0 to 100", ge=0, le=100)
    mitre_mapping: List[MitreTechnique] = Field(default_factory=list)
    provenance_explanation: str = Field(default="", description="Plain-language reading of the provenance delta")
    attribution: Attribution = Field(default_factory=Attribution)
    engine: str = Field(default="unknown", description="Which analyst produced this: gemini, heuristic, mock")


class DetectionArtifacts(BaseModel):
    """Detection rules produced by the detection-engineering stage."""
    yara_rule: str = Field(description="A complete YARA rule targeting the malicious delta")
    sigma_rule: str = Field(description="A complete Sigma rule describing the behavioural trace")
    engine: str = Field(default="unknown", description="Which engine produced this: gemini, heuristic, mock")


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
    language: str = Field(description="Detected language (python, javascript, shell, powershell, batch, unknown)")
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


class ArchiveMember(BaseModel):
    """Summary of one file analysed inside a package or archive."""
    path: str = Field(description="Member path inside the archive")
    size: int = Field(description="Uncompressed size in bytes")
    sha256: str = Field(description="SHA256 of the member's content")
    file_type: str = Field(description="Detected class of the member: pe, elf, script, document")
    language: Optional[str] = Field(default=None, description="Script language, when the member is a script")
    imports: List[str] = Field(default_factory=list)
    suspicious_calls: List[str] = Field(default_factory=list)
    high_value_strings: List[str] = Field(default_factory=list)
    encoded_blobs: List[str] = Field(default_factory=list)
    obfuscation_score: float = Field(default=0.0, ge=0.0, le=8.0)
    has_macros: bool = Field(default=False)
    source_excerpt: str = Field(default="", description="Leading source text (truncated)")


class ArchiveFeatures(BaseModel):
    """Features extracted from a software package or archive (wheel, sdist, npm tarball, zip, tar)."""
    archive_type: str = Field(description="wheel, sdist, npm, zip, tar, gzip")
    member_count: int = Field(description="Regular files listed in the archive")
    total_uncompressed_bytes: int = Field(default=0)
    package: Optional[Dict[str, str]] = Field(default=None, description="Identity from package metadata: ecosystem, name, version")
    install_hooks: List[str] = Field(default_factory=list, description="Lifecycle scripts that run at install time (e.g. npm postinstall)")
    analyzed_members: List[ArchiveMember] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list, description="Skipped members, limits hit, traversal attempts")
    imports: List[str] = Field(default_factory=list, description="Imports across analysed members")
    suspicious_calls: List[str] = Field(default_factory=list, description="Suspicious calls across analysed members")
    high_value_strings: List[str] = Field(default_factory=list, description="IOC-grade strings across analysed members")


class ExtractionResult(BaseModel):
    """
    Normalized root schema that the File Type Router produces.
    At most one of binary_features / script_features / document_features /
    archive_features is populated, depending on the detected file type.
    """
    metadata: Dict[str, Any] = Field(description="File metadata: filename, sha256, md5, size, file_type, extension_mismatch")
    file_type: str = Field(description="Canonical file class: pe, elf, script, document, archive, unknown")

    # Polymorphic feature payloads — only one is populated per analysis
    binary_features: Optional[BinaryFeatures] = Field(default=None, description="Populated for PE and ELF files")
    script_features: Optional[ScriptFeatures] = Field(default=None, description="Populated for scripts and plain text")
    document_features: Optional[DocumentFeatures] = Field(default=None, description="Populated for Office documents")
    archive_features: Optional[ArchiveFeatures] = Field(default=None, description="Populated for packages and archives")

    # Universal fields present regardless of file type
    provenance: Dict[str, Any] = Field(default_factory=lambda: {
        "ecosystem_match": "None",
        "legitimate_baseline": [],
        "injected_artifacts": []
    })
    status: str = Field(default="success")


# ─── API RESPONSE ────────────────────────────────────────────
class FinalReport(BaseModel):
    """Payload of the terminal `complete` SSE event from /api/v1/analyze."""
    schema_version: str = Field(default=SCHEMA_VERSION)
    mode: str = Field(description="Pipeline mode that produced the report: llm, heuristic, mock")
    features: ExtractionResult
    intelligence: AnalystReport
    detections: DetectionArtifacts
    warnings: List[str] = Field(default_factory=list, description="Degraded-capability and fallback notices")
    capabilities: Dict[str, bool] = Field(default_factory=dict, description="Optional tooling available to this run")
