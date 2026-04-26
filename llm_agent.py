import os
import json
import asyncio
import logging
from google import genai
from google.genai import types
from models import AnalysisResult, MitreTechnique

logger = logging.getLogger(__name__)

class IntelligenceAgent:
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY")
        self.mock_mode = not bool(self.api_key)
        
        if not self.mock_mode:
            self.client = genai.Client(api_key=self.api_key)
            self.model_id = 'gemini-2.0-flash'
        else:
            logger.warning("No GEMINI_API_KEY found! IntelligenceAgent is initializing in full MOCK MODE.")

    async def analyze_malware(self, context: dict) -> AnalysisResult:
        """
        Orchestrates the prompt execution to generate the unified AnalysisResult schema.
        Includes a robust fallback mode for safe local testing of streaming systems without burning tokens.
        """
        if self.mock_mode:
            return await self._run_mock_analysis(context)

        prompt = f"""
        You are the OriginTrace Intelligence Agent, a senior DFIR and malware reverse engineering system.
        I am passing you the raw static analysis features extracted via `pefile` and `r2pipe` from a suspect binary.

        Your objective is to:
        1. Summarize the behavioral intent and potential supply chain origin.
        2. Map definitive capabilities to MITRE ATT&CK techniques based on the imports and disassembly.
        3. Write a production-ready YARA rule specifically targeting the anomalous artifacts.
        4. Write a production-ready Sigma rule characterizing the execution signature.
        5. Assign a Threat Score out of 100.

        Ensure absolute precision and zero hallucination. Restrict detections strictly to the provided telemetry.

        RAW CONTEXT:
        {json.dumps(context, indent=2)}
        """

        try:
            # We must use asyncio.to_thread because the genai client provides a synchronous generate_content.
            response = await asyncio.to_thread(
                self.client.models.generate_content,
                model=self.model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=AnalysisResult,
                    temperature=0.1
                )
            )
            return AnalysisResult.model_validate_json(response.text)
        except Exception as e:
            logger.error(f"IntelligenceAgent LLM Error: {e}")
            raise RuntimeError(f"Intelligence Engine execution failed: {e}")

    async def _run_mock_analysis(self, context: dict) -> AnalysisResult:
        """Simulates heavy LLM operations for WebSocket/SSE testing."""
        logger.info("Executing Mock Analysis...")
        await asyncio.sleep(2) # Simulate thinking time

        filename = context.get('filename', 'unknown.exe')
        
        return AnalysisResult(
            behavioral_summary=f"MOCK: The file {filename} appears to be a heavily obfuscated dropper. Extracted entropy indicates usage of UPX packing, while r2pipe string analysis identified an encoded C2 server endpoint.",
            mitre_ttps=[
                MitreTechnique(tactic="Defense Evasion", technique_id="T1027", ai_evidence="High section entropy (>7.2) observed in .text section."),
                MitreTechnique(tactic="Command and Control", technique_id="T1071", ai_evidence="Suspect API imports (wininet.dll:InternetOpenUrlA) combined with base64 encoded strings.")
            ],
            yara_rule=f"rule mock_{filename.replace('.', '_')} {{\n  strings:\n    $s1 = \"wininet.dll\"\n    $s2 = \"MZ\"\n  condition:\n    $s2 at 0 and $s1\n}}",
            sigma_rule="title: Mock Dropper Execution\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '\\unknown.exe'\n  condition: selection\nlevel: high",
            threat_score=85
        )
