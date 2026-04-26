import json
import asyncio
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from .models import FinalReport
from .mock_agents import BinaryExtractor, ThreatAnalystAgent, DetectionEngineerAgent

app = FastAPI(title="OriginTrace Mock API")

# Allow the React frontend to communicate via CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

extractor = BinaryExtractor()
analyst = ThreatAnalystAgent()
detection_engineer = DetectionEngineerAgent()

@app.post("/api/v1/analyze")
async def analyze_binary(file: UploadFile = File(...)):
    
    async def event_generator():
        try:
            # 1. Start Extraction
            yield f'data: {json.dumps({"type": "status", "agent": "Extractor", "message": "Unpacking PE headers..."})}\n\n'
            # Sleep briefly to ensure the frontend renders the first status before the heavy parsing blocks
            await asyncio.sleep(0.5) 
            
            file_bytes = await file.read()
            features = await extractor.extract(file_bytes)
            
            # 2. Start Analyst LLM
            yield f'data: {json.dumps({"type": "status", "agent": "Analyst", "message": "Mapping behaviors to MITRE ATT&CK..."})}\n\n'
            
            analysis_report = await analyst.analyze(features)
            
            # 3. Start Detection Engineer LLM
            yield f'data: {json.dumps({"type": "status", "agent": "Detection Engineer", "message": "Compiling YARA and Sigma signatures..."})}\n\n'
            
            rules = await detection_engineer.generate_rules(analysis_report)
            
            # 4. Finish Pipeline
            final_report = FinalReport(
                hashes=features["hashes"],
                intelligence=analysis_report,
                detections=rules
            )
            
            yield f'data: {json.dumps({"type": "complete", "data": final_report.model_dump()})}\n\n'
            
        except Exception as e:
            yield f'data: {json.dumps({"type": "error", "message": str(e)})}\n\n'

    return StreamingResponse(event_generator(), media_type="text/event-stream")
