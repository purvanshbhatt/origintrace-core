"""End-to-end tests for the FastAPI analysis pipeline."""
import hashlib
import json
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import main
from agents.heuristic import HeuristicAnalystAgent, HeuristicDetectionEngineerAgent
from conftest import BENIGN_PYTHON, MALICIOUS_PYTHON, make_wheel
from extractors.extractor import MasterBinaryExtractor
from models import FinalReport


def _events(response: Any) -> list[dict[str, Any]]:
    """Parse an SSE body into its JSON payloads."""
    events = []
    for line in response.text.splitlines():
        if line.startswith("data: "):
            events.append(json.loads(line[len("data: "):]))
    return events


def _upload(client: TestClient, name: str, content: bytes) -> Any:
    return client.post("/api/v1/analyze", files={"file": (name, content, "application/octet-stream")})


@pytest.fixture
def heuristic_client() -> TestClient:
    return TestClient(main.create_app(mode="heuristic"))


@pytest.fixture
def mock_client() -> TestClient:
    return TestClient(main.create_app(mode="mock"))


# ── Service endpoints ────────────────────────────────────────

def test_root_and_health(heuristic_client: TestClient) -> None:
    assert heuristic_client.get("/").status_code == 200

    health = heuristic_client.get("/health")
    body = health.json()
    assert health.status_code == 200
    assert body["status"] == "healthy"
    assert body["mode"] == "heuristic"
    assert isinstance(body["capabilities"], dict)


def test_mode_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("USE_MOCK", raising=False)
    monkeypatch.delenv("ORIGINTRACE_MODE", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert main.resolve_mode() == "heuristic"

    monkeypatch.setenv("GEMINI_API_KEY", "k")
    assert main.resolve_mode() == "llm"

    monkeypatch.setenv("USE_MOCK", "true")
    assert main.resolve_mode() == "mock"

    monkeypatch.setenv("ORIGINTRACE_MODE", "heuristic")
    assert main.resolve_mode() == "heuristic"
    assert main.resolve_mode("mock") == "mock"


# ── Analysis pipeline ────────────────────────────────────────

def test_heuristic_pipeline_analyzes_a_real_sample(heuristic_client: TestClient) -> None:
    content = MALICIOUS_PYTHON.encode()
    response = _upload(heuristic_client, "dropper.py", content)
    events = _events(response)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert [e["type"] for e in events if e["type"] != "status"] == ["complete"]
    assert {e["agent"] for e in events if e["type"] == "status"} >= {"Extractor", "Analyst", "Detection Engineer"}

    report = events[-1]["data"]
    FinalReport.model_validate(report)
    assert report["mode"] == "heuristic"
    assert report["features"]["metadata"]["filename"] == "dropper.py"
    assert report["features"]["metadata"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert report["intelligence"]["threat_level"] == "High"
    assert "T1059.006" in {t["technique_id"] for t in report["intelligence"]["mitre_mapping"]}
    assert "http://185.220.101.7/drop/stage2.bin" in report["detections"]["yara_rule"]
    assert report["detections"]["sigma_rule"].startswith("title:")


def test_heuristic_pipeline_rates_benign_sample_low(heuristic_client: TestClient) -> None:
    events = _events(_upload(heuristic_client, "geometry.py", BENIGN_PYTHON.encode()))
    assert events[-1]["type"] == "complete"
    assert events[-1]["data"]["intelligence"]["threat_level"] == "Low"


def test_mock_pipeline_uses_real_hashes_and_shared_contract(mock_client: TestClient) -> None:
    content = b"MZ" + b"\x00" * 128
    events = _events(_upload(mock_client, "demo.exe", content))

    assert events[-1]["type"] == "complete"
    report = events[-1]["data"]
    FinalReport.model_validate(report)
    assert report["mode"] == "mock"
    assert report["features"]["metadata"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert report["features"]["metadata"]["size"] == len(content)
    assert report["intelligence"]["engine"] == "mock"


def test_package_upload_is_unpacked_and_attributed(heuristic_client: TestClient, tmp_path: Path) -> None:
    content = make_wheel(tmp_path / "pkg.whl").read_bytes()
    events = _events(_upload(heuristic_client, "totally_legit-1.0-py3-none-any.whl", content))

    assert events[-1]["type"] == "complete"
    report = events[-1]["data"]
    FinalReport.model_validate(report)
    assert report["features"]["file_type"] == "archive"
    assert report["features"]["archive_features"]["package"]["name"] == "totally-legit"
    assert report["intelligence"]["threat_level"] == "High"
    assert report["intelligence"]["attribution"]["suspected_package"] == "totally-legit"
    assert any("member" in e["message"] for e in events if e["type"] == "status")


def test_large_complete_event_is_a_single_sse_line(heuristic_client: TestClient) -> None:
    content = (MALICIOUS_PYTHON + "\n# pad\n" * 4000).encode()
    response = _upload(heuristic_client, "big.py", content)
    data_lines = [line for line in response.text.splitlines() if line.startswith("data: ")]
    assert json.loads(data_lines[-1][6:])["type"] == "complete"


# ── Upload validation ────────────────────────────────────────

def test_oversized_upload_is_rejected() -> None:
    client = TestClient(main.create_app(mode="mock", max_upload_bytes=1024))
    response = _upload(client, "big.bin", b"A" * 4096)
    assert response.status_code == 413


def test_empty_upload_is_rejected(mock_client: TestClient) -> None:
    assert _upload(mock_client, "empty.bin", b"").status_code == 400


def test_missing_file_field_is_rejected(mock_client: TestClient) -> None:
    assert mock_client.post("/api/v1/analyze").status_code == 422


def test_filename_is_reduced_to_a_basename(heuristic_client: TestClient) -> None:
    events = _events(_upload(heuristic_client, "..\\..\\evil.py", BENIGN_PYTHON.encode()))
    assert events[-1]["data"]["features"]["metadata"]["filename"] == "evil.py"


def test_temp_files_are_removed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    client = TestClient(main.create_app(mode="heuristic"))

    _upload(client, "dropper.py", MALICIOUS_PYTHON.encode())
    _upload(TestClient(main.create_app(mode="mock", max_upload_bytes=16)), "big.bin", b"A" * 64)

    assert list(tmp_path.glob("origintrace_*")) == []


# ── Failure handling ─────────────────────────────────────────

class _BrokenExtractor:
    def extract_all(self, file_path: str, filename: str) -> dict[str, Any]:
        raise RuntimeError("boom")


class _SlowExtractor:
    def extract_all(self, file_path: str, filename: str) -> dict[str, Any]:
        time.sleep(2)
        return {}


class _FailingAgent:
    async def analyze(self, malware_context: dict[str, Any]) -> Any:
        raise RuntimeError("gemini unavailable")

    async def generate_rules(self, malware_context: dict[str, Any], analyst_report: dict[str, Any]) -> Any:
        raise RuntimeError("gemini unavailable")


def _engines(**overrides: Any) -> main.Engines:
    defaults: dict[str, Any] = {
        "mode": "heuristic",
        "extractor": MasterBinaryExtractor(),
        "analyst": HeuristicAnalystAgent(),
        "detector": HeuristicDetectionEngineerAgent(),
    }
    defaults.update(overrides)
    return main.Engines(**defaults)


def test_extractor_crash_is_reported_as_an_error_event() -> None:
    client = TestClient(main.create_app(engines=_engines(extractor=_BrokenExtractor())))
    events = _events(_upload(client, "x.py", b"print(1)\n"))

    assert events[-1]["type"] == "error"
    assert "boom" in events[-1]["message"]


def test_extraction_timeout_has_a_readable_message() -> None:
    app = main.create_app(engines=_engines(extractor=_SlowExtractor()), extraction_timeout_s=0.2)
    events = _events(_upload(TestClient(app), "x.py", b"print(1)\n"))

    assert events[-1]["type"] == "error"
    assert "timed out" in events[-1]["message"].lower()


def test_llm_failure_falls_back_to_heuristics() -> None:
    engines = _engines(
        mode="llm",
        analyst=_FailingAgent(),
        detector=_FailingAgent(),
        fallback_analyst=HeuristicAnalystAgent(),
        fallback_detector=HeuristicDetectionEngineerAgent(),
    )
    events = _events(_upload(TestClient(main.create_app(engines=engines)), "dropper.py", MALICIOUS_PYTHON.encode()))

    assert events[-1]["type"] == "complete"
    report = events[-1]["data"]
    assert report["intelligence"]["engine"] == "heuristic"
    assert report["detections"]["engine"] == "heuristic"
    assert any("gemini unavailable" in w for w in report["warnings"])


def test_llm_failure_without_fallback_is_an_error() -> None:
    engines = _engines(mode="llm", analyst=_FailingAgent())
    events = _events(_upload(TestClient(main.create_app(engines=engines)), "x.py", b"print(1)\n"))
    assert events[-1]["type"] == "error"
    assert "gemini unavailable" in events[-1]["message"]


# ── CORS ─────────────────────────────────────────────────────

def test_cors_honours_allowed_origins_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://soc.example, https://lab.example")
    client = TestClient(main.create_app(mode="mock"))

    allowed = client.get("/health", headers={"Origin": "https://lab.example"})
    denied = client.get("/health", headers={"Origin": "https://evil.example"})

    assert allowed.headers["access-control-allow-origin"] == "https://lab.example"
    assert "access-control-allow-origin" not in denied.headers


def test_cors_defaults_cover_local_dev_and_hosting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    client = TestClient(main.create_app(mode="mock"))
    for origin in ("http://localhost:5173", "https://origintrace-ui.web.app"):
        response = client.get("/health", headers={"Origin": origin})
        assert response.headers["access-control-allow-origin"] == origin
