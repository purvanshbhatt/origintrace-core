/**
 * API contract for POST /api/v1/analyze.
 * Mirrors the Pydantic models in `models.py` at the repository root —
 * change both together.
 */

export interface MitreTechnique {
  tactic: string;
  technique_id: string;
  technique_name?: string;
  evidence: string;
}

export interface Attribution {
  ecosystem: string;
  suspected_package?: string | null;
}

export interface AnalystReport {
  behavioral_summary: string;
  threat_level: string;
  threat_score: number;
  mitre_mapping: MitreTechnique[];
  provenance_explanation: string;
  attribution: Attribution;
  /** Which analyst produced this: gemini, heuristic, mock. */
  engine: string;
}

export interface DetectionArtifacts {
  yara_rule: string;
  sigma_rule: string;
  engine: string;
}

export interface FileMetadata {
  filename: string;
  sha256: string | null;
  md5: string | null;
  size: number | null;
  file_type: string;
  extension_mismatch?: boolean;
}

export interface DecompiledFunction {
  name: string;
  decompiled_c: string;
  symbolic_resolved_strings: string[];
  calls_api?: string;
}

export interface BinaryFeatures {
  imports: string[];
  sections: string[];
  functions: DecompiledFunction[];
  high_value_strings: string[];
  imphash?: string | null;
  elf_type?: string | null;
  elf_machine?: string | null;
  elf_symbols?: string[];
}

export interface ScriptFeatures {
  language: string;
  raw_source: string;
  ast_imports: string[];
  suspicious_calls: string[];
  encoded_blobs: string[];
  obfuscation_score: number;
  high_value_strings: string[];
}

export interface DocumentFeatures {
  doc_type: string;
  has_macros: boolean;
  macro_source: string | null;
  suspicious_keywords: string[];
  embedded_urls: string[];
  embedded_ole_objects: string[];
  high_value_strings: string[];
}

export interface Provenance {
  ecosystem_match: string;
  legitimate_baseline: string[];
  injected_artifacts: string[];
  engine?: string;
}

export interface ExtractionResult {
  metadata: FileMetadata;
  file_type: string;
  binary_features: BinaryFeatures | null;
  script_features: ScriptFeatures | null;
  document_features: DocumentFeatures | null;
  provenance: Provenance;
  status: string;
}

export interface FinalReport {
  schema_version: string;
  /** Pipeline mode that produced the report: llm, heuristic, mock. */
  mode: string;
  features: ExtractionResult;
  intelligence: AnalystReport;
  detections: DetectionArtifacts;
  warnings: string[];
  capabilities: Record<string, boolean>;
}

export type StreamEvent =
  | { type: 'status'; agent: string; message: string }
  | { type: 'complete'; data: FinalReport }
  | { type: 'error'; message: string };
