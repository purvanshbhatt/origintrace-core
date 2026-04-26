import os
import json
from google import genai
from google.genai import types
from models import AnalysisResult

class OriginTraceAIAgent:
    """
    Orchestrates connection to the Google GenAI API (Gemini).
    Designed to enforce strict grammar logic via response_schema mapping
    zero-false-positive constraints on YARA/Sigma generated rules.
    """
    def __init__(self):
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is absolutely required.")
        
        # Initialize the modern official SDK
        self.client = genai.Client(api_key=api_key)
        
        # Upgraded to gemini-3.0-flash leveraging the "Flash-Lite Sandwich" architecture
        self.model_id = "gemini-3.0-flash"

    async def analyze_malware(self, extraction_manifest: dict) -> AnalysisResult:
        # 1. Component Extraction for Sandwich Architecture
        metadata = extraction_manifest.get("metadata", {})
        provenance = extraction_manifest.get("provenance", {})
        
        # Shallow copy static features to extract the heavy disassembly out of the middle
        static_features = dict(extraction_manifest.get("static_features", {}))
        suspicious_functions = static_features.pop("suspicious_functions", [])
        
        # 2. Strict Constraints & Instructions
        system_instruction = """You are the OriginTrace Threat Intelligence Analyst & Detection Engineer.
You are provided with a technical extraction manifest of a suspected Windows PE or raw binary.

Your tasks:
1. Summarize the behavioral capability of this binary.
2. Map the extracted strings, API imports, and disassembled behaviors to MITRE ATT&CK techniques.
3. Identify if the binary matches a hijacked supply chain entity or is native/standalone malware (Attribution). Provide this explicitly in your behavior summary.
4. Write ONE valid, production-ready YARA rule.
5. Write ONE valid, production-ready Sigma rule characterizing the execution phase.

CRITICAL REQUIREMENT: If the provenance section reveals a "legitimate_baseline", you MUST NOT include those legitimate strings or imports in your YARA/Sigma rules. You must write rules strictly targeting the "injected_artifacts" to guarantee 0% false positives on standard library code.

CRITICAL INSTRUCTION: When mapping a MITRE ATT&CK technique in the `mitre_mapping` array, you MUST quote the exact imported function, string, or assembly instruction from the provided MaliciousContext in the `ai_evidence` field. Do not generalize. Provide concrete proof from the data."""
        
        # 3. Construct the "Flash-Lite Sandwich" Payload
        sandwich_prompt = f"""[SYSTEM INSTRUCTIONS AND RULES]
{system_instruction}

[STATIC METADATA]
{json.dumps(metadata, indent=2)}

[PROVENANCE]
{json.dumps(provenance, indent=2)}

[IMPORTS & FILTERED IOC STRINGS]
{json.dumps(static_features, indent=2)}

[HEAVY CONTEXT: SUSPICIOUS FUNCTIONS DISASSEMBLY]
{json.dumps(suspicious_functions, indent=2)}

Analyze the structured payload above and return the required JSON object."""
        
        # 4. Strict Pydantic JSON Grammar Enforcement
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=AnalysisResult,
            temperature=0.1, # Keep low to ensure deterministic analytical mapping
        )

        # Asynchronously dispatch to Gemini 3.0 Flash
        response = await self.client.aio.models.generate_content(
            model=self.model_id,
            contents=sandwich_prompt,
            config=config
        )

        return AnalysisResult.model_validate_json(response.text)
