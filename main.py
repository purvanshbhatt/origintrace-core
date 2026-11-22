"""
OriginTrace Engine API

FastAPI service that runs an uploaded file through a three-stage pipeline
(extraction → threat analysis → detection engineering) and streams progress
to the client as Server-Sent Events.

Modes (ORIGINTRACE_MODE, or inferred from the environment):
  llm        Real extraction + Gemini agents. Requires GEMINI_API_KEY. Falls
             back to the heuristic agents if a Gemini call fails.
  heuristic  Real extraction + offline rule-based agents. No API key needed.
  mock       Canned demo data (USE_MOCK=true). Only the file hashes are real.

SSE contract of POST /api/v1/analyze (one JSON object per `data:` line):
  {"type": "status",   "agent": str, "message": str}
  {"type": "complete", "data": FinalReport}        (see models.py)
  {"type": "error",    "message": str}
"""
import asyncio
import json
import logging
import os
import re
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from models import SCHEMA_VERSION

logger = logging.getLogger("origintrace.api")

API_VERSION = "1.1.0"
VALID_MODES = ("mock", "heuristic", "llm")

DEFAULT_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5174",
    "https://origintrace-ui.web.app",
    "https://origintrace-ui.firebaseapp.com",
]

# Cloud Run rejects HTTP/1 request bodies above 32 MiB, so that is the ceiling.
DEFAULT_MAX_UPLOAD_MB = 32
DEFAULT_EXTRACTION_TIMEOUT_S = 120.0
UPLOAD_CHUNK_BYTES = 1024 * 1024
MAX_ERROR_CHARS = 300

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class Engines:
    """The three pipeline stages, plus optional fallbacks for the LLM stages."""
    mode: str
    extractor: Any
    analyst: Any
    detector: Any
    fallback_analyst: Any = None
    fallback_detector: Any = None


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        logger.warning(f"Ignoring non-numeric {name}; using {default}")
        return default


def allowed_origins() -> List[str]:
    """CORS origins: ALLOWED_ORIGINS (comma-separated) or the built-in defaults."""
    configured = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
    return configured or list(DEFAULT_ORIGINS)


def resolve_mode(explicit: Optional[str] = None) -> str:
    """Decide the pipeline mode from an explicit value or the environment."""
    for candidate in (explicit, os.environ.get("ORIGINTRACE_MODE")):
        candidate = (candidate or "").strip().lower()
        if candidate in VALID_MODES:
            return candidate
    if os.environ.get("USE_MOCK", "false").strip().lower() == "true":
        return "mock"
    return "llm" if os.environ.get("GEMINI_API_KEY") else "heuristic"


def build_engines(mode: str) -> Engines:
    """Instantiate the pipeline stages for ``mode``."""
    if mode == "mock":
        from mock_api.mock_agents import BinaryExtractor, DetectionEngineerAgent, ThreatAnalystAgent
        return Engines("mock", BinaryExtractor(), ThreatAnalystAgent(), DetectionEngineerAgent())

    from agents.heuristic import HeuristicAnalystAgent, HeuristicDetectionEngineerAgent
    from extractors.extractor import MasterBinaryExtractor

    extractor = MasterBinaryExtractor()
    heuristic_analyst = HeuristicAnalystAgent()
    heuristic_detector = HeuristicDetectionEngineerAgent()

    if mode == "llm":
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            logger.warning("llm mode requested without GEMINI_API_KEY; using heuristic agents")
        else:
            try:
                from agents.analyst import ThreatAnalystAgent
                from agents.detection_engineer import DetectionEngineerAgent
                return Engines(
                    "llm", extractor,
                    ThreatAnalystAgent(api_key=api_key),
                    DetectionEngineerAgent(api_key=api_key),
                    fallback_analyst=heuristic_analyst,
                    fallback_detector=heuristic_detector,
                )
            except Exception as e:
                logger.error(f"Gemini agents unavailable ({type(e).__name__}: {e}); using heuristic agents")

    return Engines("heuristic", extractor, heuristic_analyst, heuristic_detector)


def _capabilities() -> Dict[str, bool]:
    try:
        from extractors.extractor import get_capabilities
        return get_capabilities()
    except Exception as e:
        logger.warning(f"Capability probe failed: {e}")
        return {}


def _safe_filename(raw: Optional[str]) -> str:
    """Reduce a client-supplied filename to a bare, printable basename."""
    name = (raw or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = _CONTROL_CHARS_RE.sub("", name).strip()[:255]
    return name or "upload.bin"


def _remove(path: Optional[str]) -> None:
    if not path:
        return
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.warning(f"Could not remove temp file {path}: {e}")


async def _spool_upload(file: UploadFile, max_bytes: int) -> Tuple[str, int]:
    """
    Copy the upload to a temp file, enforcing the size limit.

    This runs inside the request handler, before the streaming response is
    returned: FastAPI closes the UploadFile as soon as the handler returns,
    so it must not be read from inside the response generator.
    """
    fd, path = tempfile.mkstemp(prefix="origintrace_", suffix=".bin")
    size = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while chunk := await file.read(UPLOAD_CHUNK_BYTES):
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds the {max_bytes // (1024 * 1024)} MB upload limit.",
                    )
                out.write(chunk)
        if size == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    except BaseException:
        _remove(path)
        raise
    return path, size


def _sse(payload: Dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, default=str)}\n\n"


def _status(agent: str, message: str) -> str:
    return _sse({"type": "status", "agent": agent, "message": message})


def _error(message: str) -> str:
    return _sse({"type": "error", "message": message})


def _describe(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    return text[:MAX_ERROR_CHARS]


def _dump(model: Any) -> Dict[str, Any]:
    return model.model_dump() if hasattr(model, "model_dump") else dict(model)


def _extraction_summary(features: Dict[str, Any]) -> str:
    """One-line progress message describing what extraction found."""
    file_type = features.get("file_type", "unknown")
    indicators = 0
    for key in ("binary_features", "script_features", "document_features"):
        payload = features.get(key) or {}
        indicators += len(payload.get("high_value_strings") or [])
    return f"Classified as {file_type}; {indicators} indicator(s) extracted."


async def _event_stream(engines: Engines, temp_path: str, filename: str,
                        extraction_timeout_s: float,
                        capabilities: Dict[str, bool]) -> AsyncIterator[str]:
    """Run the pipeline and yield SSE lines. Always removes the temp file."""
    warnings: List[str] = []
    try:
        # Step 1: Extraction
        yield _status("Extractor", "Identifying file type and extracting features...")
        try:
            # Extraction is blocking (r2, angr); keep it off the event loop and
            # bound it so a malformed binary cannot hold the request forever.
            features = await asyncio.wait_for(
                asyncio.to_thread(engines.extractor.extract_all, temp_path, filename),
                timeout=extraction_timeout_s,
            )
        except asyncio.TimeoutError:
            yield _error(
                f"Extraction timed out after {extraction_timeout_s:g}s. "
                "The sample may be too large or malformed for static analysis."
            )
            return
        except Exception as e:
            logger.exception("Extraction failed")
            yield _error(f"Extraction failed: {_describe(e)}")
            return

        extraction_status = str(features.get("status", "success"))
        if not extraction_status.startswith("success"):
            warnings.append(f"Extractor: {extraction_status}")
        yield _status("Extractor", _extraction_summary(features))

        # Step 2: Analyst
        yield _status("Analyst", "Mapping behaviors to MITRE ATT&CK...")
        try:
            analysis_report = await engines.analyst.analyze(features)
        except Exception as e:
            if engines.fallback_analyst is None:
                logger.exception("Analysis failed")
                yield _error(f"Analysis failed: {_describe(e)}")
                return
            logger.warning(f"Analyst failed, using fallback: {_describe(e)}")
            warnings.append(f"Analyst ({engines.mode}) failed, used heuristic fallback: {_describe(e)}")
            yield _status("Analyst", "LLM unavailable; falling back to heuristic rules...")
            analysis_report = await engines.fallback_analyst.analyze(features)
        intelligence = _dump(analysis_report)

        # Step 3: Detection Engineer
        yield _status("Detection Engineer", "Compiling YARA and Sigma signatures...")
        try:
            rules = await engines.detector.generate_rules(
                malware_context=features,
                analyst_report=intelligence,
            )
        except Exception as e:
            if engines.fallback_detector is None:
                logger.exception("Detection engineering failed")
                yield _error(f"Detection engineering failed: {_describe(e)}")
                return
            logger.warning(f"Detection engineer failed, using fallback: {_describe(e)}")
            warnings.append(f"Detection Engineer ({engines.mode}) failed, used heuristic fallback: {_describe(e)}")
            yield _status("Detection Engineer", "LLM unavailable; falling back to heuristic rules...")
            rules = await engines.fallback_detector.generate_rules(
                malware_context=features,
                analyst_report=intelligence,
            )

        # Combine Final Report
        final_report = {
            "schema_version": SCHEMA_VERSION,
            "mode": engines.mode,
            "features": features,
            "intelligence": intelligence,
            "detections": _dump(rules),
            "warnings": warnings,
            "capabilities": capabilities,
        }
        yield _sse({"type": "complete", "data": final_report})

    except Exception as e:
        logger.exception("Pipeline failed")
        yield _error(f"Pipeline failed: {_describe(e)}")
    finally:
        _remove(temp_path)


def create_app(mode: Optional[str] = None, *, engines: Optional[Engines] = None,
               max_upload_bytes: Optional[int] = None,
               extraction_timeout_s: Optional[float] = None) -> FastAPI:
    """
    Build the FastAPI application.

    Args:
        mode: Force a pipeline mode (mock | heuristic | llm).
        engines: Inject pipeline stages directly (used by tests).
        max_upload_bytes: Upload size limit; defaults to MAX_UPLOAD_MB.
        extraction_timeout_s: Extraction budget; defaults to EXTRACTION_TIMEOUT_S.
    """
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=os.environ.get("LOG_LEVEL", "INFO").upper(),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )

    engines = engines or build_engines(resolve_mode(mode))
    upload_limit = max_upload_bytes or int(_env_float("MAX_UPLOAD_MB", DEFAULT_MAX_UPLOAD_MB) * 1024 * 1024)
    timeout_s = extraction_timeout_s or _env_float("EXTRACTION_TIMEOUT_S", DEFAULT_EXTRACTION_TIMEOUT_S)
    capabilities = _capabilities()
    logger.info(f"OriginTrace API starting in {engines.mode.upper()} mode")

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        # Load the provenance model in the background so the first upload
        # does not pay for it.
        warm_up = getattr(engines.extractor, "warm_up", None)
        task = asyncio.create_task(asyncio.to_thread(warm_up)) if callable(warm_up) else None
        try:
            yield
        finally:
            if task is not None and not task.done():
                task.cancel()

    app = FastAPI(
        title="OriginTrace Engine API",
        description="Malware Static Analysis & Supply Chain Attribution Pipeline",
        version=API_VERSION,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.get("/")
    async def root() -> Dict[str, str]:
        return {"status": "online", "message": "OriginTrace API is running. Send POST requests to /api/v1/analyze."}

    @app.get("/health")
    async def health_check() -> Dict[str, Any]:
        return {
            "status": "healthy",
            "service": "origintrace-engine-backend",
            "version": API_VERSION,
            "mode": engines.mode,
            "capabilities": capabilities,
            "limits": {"max_upload_bytes": upload_limit, "extraction_timeout_s": timeout_s},
        }

    @app.post("/api/v1/analyze")
    async def analyze_binary(file: UploadFile = File(...)) -> StreamingResponse:
        filename = _safe_filename(file.filename)
        temp_path, size = await _spool_upload(file, upload_limit)
        logger.info(f"Analyzing '{filename}' ({size} bytes) in {engines.mode} mode")
        return StreamingResponse(
            _event_stream(engines, temp_path, filename, timeout_s, capabilities),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return app


app = create_app()
