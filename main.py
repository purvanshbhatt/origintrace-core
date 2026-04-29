import os
import json
import time
import asyncio
import tempfile
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

# Initialize FastAPI
app = FastAPI(
    title="OriginTrace Engine API",
    description="High-Throughput Malware Detonation & LLM Attribution Pipeline",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_key = os.environ.get("GEMINI_API_KEY")
USE_MOCK = os.environ.get("USE_MOCK", "false").lower() == "true" or not api_key

if USE_MOCK:
    print("[!] Running in MOCK MODE (GEMINI_API_KEY missing or USE_MOCK=true)")
    from mock_api.mock_agents import BinaryExtractor, ThreatAnalystAgent, DetectionEngineerAgent
    extractor_service = BinaryExtractor()
    analyst_service = ThreatAnalystAgent()
    detection_service = DetectionEngineerAgent()
else:
    print("[*] Running in PRODUCTION MODE with Gemini 3.0 Flash Preview")
    from extractors.extractor import MasterBinaryExtractor
    from agents.analyst import ThreatAnalystAgent
    from agents.detection_engineer import DetectionEngineerAgent
    extractor_service = MasterBinaryExtractor()
    analyst_service = ThreatAnalystAgent(api_key=api_key)
    detection_service = DetectionEngineerAgent(api_key=api_key)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "origintrace-engine-backend"}

@app.post("/api/v1/analyze")
async def analyze_binary(file: UploadFile = File(...)):
    async def event_generator():
        temp_path = None
        try:
            # Step 1: Extraction
            yield f'data: {json.dumps({"type": "status", "agent": "Extractor", "message": "Unpacking PE headers..."})}\n\n'
            await asyncio.sleep(0.5)
            
            if USE_MOCK:
                file_bytes = await file.read()
                features = await extractor_service.extract(file_bytes)
            else:
                temp_fd, temp_path = tempfile.mkstemp(prefix="origintrace_", suffix=".bin")
                with os.fdopen(temp_fd, 'wb') as f:
                    while chunk := await file.read(8 * 1024 * 1024):
                        f.write(chunk)
                features = await extractor_service.extract_all(file_path=temp_path, filename=file.filename)
            
            # Step 2: Analyst
            yield f'data: {json.dumps({"type": "status", "agent": "Analyst", "message": "Mapping behaviors to MITRE ATT&CK..."})}\n\n'
            
            if USE_MOCK:
                analysis_report = await analyst_service.analyze(features)
            else:
                analysis_report = await analyst_service.analyze(features)
                
            # Step 3: Detection Engineer
            yield f'data: {json.dumps({"type": "status", "agent": "Detection Engineer", "message": "Compiling YARA and Sigma signatures..."})}\n\n'
            
            if USE_MOCK:
                rules = await detection_service.generate_rules(analysis_report)
            else:
                rules = await detection_service.generate_rules(
                    malware_context=features, 
                    analyst_report=analysis_report.model_dump()
                )
            
            # Combine Final Report
            intelligence_dict = analysis_report.model_dump() if hasattr(analysis_report, "model_dump") else analysis_report
            rules_dict = rules.model_dump() if hasattr(rules, "model_dump") else rules
            
            final_report = {
                "features": features,
                "intelligence": intelligence_dict,
                "detections": rules_dict
            }
            
            yield f'data: {json.dumps({"type": "complete", "data": final_report})}\n\n'
            
        except Exception as e:
            yield f'data: {json.dumps({"type": "error", "message": str(e)})}\n\n'
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
