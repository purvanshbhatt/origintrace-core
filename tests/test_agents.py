"""Tests for the heuristic and Gemini-backed agents."""
import asyncio
import copy
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agents.context import attribution_from_provenance, build_llm_context
from agents.heuristic import (
    HeuristicAnalystAgent,
    HeuristicDetectionEngineerAgent,
    build_sigma_rule,
    build_yara_rule,
)
from conftest import BENIGN_PYTHON, MALICIOUS_PYTHON, REVERSE_SHELL, make_npm_tarball, make_wheel
from extractors.extractor import MasterBinaryExtractor
from models import AnalystReport, DetectionArtifacts


def _features(write_sample, name: str, content: str) -> dict[str, Any]:
    path = write_sample(name, content)
    return MasterBinaryExtractor().extract_all(str(path), name)


def _technique_ids(report: AnalystReport) -> set[str]:
    return {t.technique_id for t in report.mitre_mapping}


def _analyze(features: dict[str, Any]) -> AnalystReport:
    return asyncio.run(HeuristicAnalystAgent().analyze(features))


def _rules(features: dict[str, Any], report: AnalystReport) -> DetectionArtifacts:
    agent = HeuristicDetectionEngineerAgent()
    return asyncio.run(agent.generate_rules(malware_context=features, analyst_report=report.model_dump()))


# ── Heuristic analyst ────────────────────────────────────────

def test_malicious_python_is_high_severity(write_sample) -> None:
    report = _analyze(_features(write_sample, "dropper.py", MALICIOUS_PYTHON))

    assert report.engine == "heuristic"
    assert report.threat_level == "High"
    assert 65 <= report.threat_score <= 100
    assert {"T1059.006", "T1105", "T1140"} <= _technique_ids(report)
    assert all(t.evidence and t.technique_name and t.tactic for t in report.mitre_mapping)
    assert "dropper.py" in report.behavioral_summary


def test_reverse_shell_maps_persistence_and_c2(write_sample) -> None:
    report = _analyze(_features(write_sample, "install.sh", REVERSE_SHELL))
    assert {"T1059.004", "T1053.003", "T1105", "T1095"} <= _technique_ids(report)
    assert report.threat_level == "High"


def test_benign_script_is_low_severity(write_sample) -> None:
    report = _analyze(_features(write_sample, "geometry.py", BENIGN_PYTHON))
    assert report.threat_level == "Low"
    assert report.threat_score < 30
    assert report.mitre_mapping == []
    assert "not a clean bill of health" in report.behavioral_summary.lower()


def test_autoexec_macro_document_is_flagged() -> None:
    features = {
        "metadata": {"filename": "invoice.docm", "sha256": "a" * 64, "file_type": "document"},
        "file_type": "document",
        "binary_features": None,
        "script_features": None,
        "document_features": {
            "doc_type": "OpenXML",
            "has_macros": True,
            "macro_source": 'Sub AutoOpen()\n Shell "powershell -enc AAAA"\nEnd Sub',
            "suspicious_keywords": ["AutoOpen", "Shell", "PowerShell"],
            "embedded_urls": [],
            "embedded_ole_objects": [],
            "high_value_strings": [],
        },
        "provenance": {"ecosystem_match": "None", "legitimate_baseline": [], "injected_artifacts": []},
        "status": "success",
    }
    assert {"T1204.002", "T1059.005", "T1059.001"} <= _technique_ids(_analyze(features))


def test_process_injection_imports_are_flagged() -> None:
    features = {
        "metadata": {"filename": "implant.exe", "sha256": "b" * 64, "file_type": "pe"},
        "file_type": "pe",
        "binary_features": {
            "imports": [
                "kernel32.dll:VirtualAllocEx",
                "kernel32.dll:WriteProcessMemory",
                "kernel32.dll:CreateRemoteThread",
            ],
            "sections": [".text (Entropy: 7.81)"],
            "functions": [],
            "high_value_strings": [],
        },
        "script_features": None,
        "document_features": None,
        "provenance": {"ecosystem_match": "None", "legitimate_baseline": [], "injected_artifacts": []},
        "status": "success",
    }
    report = _analyze(features)
    assert {"T1055", "T1027"} <= _technique_ids(report)
    assert any("CreateRemoteThread" in t.evidence for t in report.mitre_mapping)


def test_supply_chain_match_drives_attribution(write_sample) -> None:
    features = _features(write_sample, "dropper.py", MALICIOUS_PYTHON)
    features["provenance"] = {
        "ecosystem_match": "PyPI: requests-v2 (87% similarity)",
        "legitimate_baseline": ["requests.get"],
        "injected_artifacts": ["http://185.220.101.7/exfil"],
    }
    report = _analyze(features)

    assert "T1195.002" in _technique_ids(report)
    assert report.attribution.ecosystem == "PyPI"
    assert report.attribution.suspected_package == "requests-v2"
    assert "requests-v2" in report.provenance_explanation


@pytest.mark.parametrize(
    ("ecosystem_match", "ecosystem", "package"),
    [
        ("PyPI: requests-v2 (87% similarity)", "PyPI", "requests-v2"),
        ("NPM: express-js (91% similarity)", "NPM", "express-js"),
        ("Native/Unknown (Best match: 12%)", "Native/Unknown", None),
        ("None", "Unknown", None),
        ("", "Unknown", None),
    ],
)
def test_attribution_from_provenance(ecosystem_match: str, ecosystem: str, package: str | None) -> None:
    attribution = attribution_from_provenance({"ecosystem_match": ecosystem_match})
    assert attribution.ecosystem == ecosystem
    assert attribution.suspected_package == package


def test_build_llm_context_trims_without_mutating() -> None:
    features = {
        "metadata": {"filename": "big.elf"},
        "file_type": "elf",
        "binary_features": {
            "imports": [f"imp{i}" for i in range(900)],
            "elf_symbols": [f"sym{i}" for i in range(5000)],
            "functions": [{"name": "entry0", "decompiled_c": "x" * 9000, "symbolic_resolved_strings": []}],
            "high_value_strings": [f"http://h{i}.example/" for i in range(700)],
            "sections": [],
        },
        "provenance": {"injected_artifacts": [f"a{i}" for i in range(900)]},
    }
    original = copy.deepcopy(features)

    trimmed = build_llm_context(features)

    assert features == original
    assert len(trimmed["binary_features"]["imports"]) <= 200
    assert len(trimmed["binary_features"]["elf_symbols"]) <= 200
    assert len(trimmed["binary_features"]["high_value_strings"]) <= 150
    assert len(trimmed["binary_features"]["functions"][0]["decompiled_c"]) <= 4100
    assert len(trimmed["provenance"]["injected_artifacts"]) <= 150


def test_mentions_in_docstrings_do_not_raise_severity(write_sample) -> None:
    source = '"""Never call eval() or exec() on user input."""\nimport re\nPATTERN = re.compile("x")\n'
    report = _analyze(_features(write_sample, "doc.py", source))
    assert report.mitre_mapping == []
    assert report.threat_level == "Low"


def test_malicious_wheel_is_attributed_to_its_package(tmp_path: Path) -> None:
    path = make_wheel(tmp_path / "totally_legit-1.0-py3-none-any.whl")
    report = _analyze(MasterBinaryExtractor().extract_all(str(path), path.name))

    assert report.threat_level == "High"
    assert {"T1059.006", "T1105", "T1140"} <= _technique_ids(report)
    assert report.attribution.ecosystem == "PyPI"
    assert report.attribution.suspected_package == "totally-legit"
    # Evidence names the member it came from.
    assert any("totally_legit/__init__.py" in t.evidence for t in report.mitre_mapping)
    assert "totally-legit" in report.provenance_explanation


def test_npm_install_hook_is_flagged(tmp_path: Path) -> None:
    path = make_npm_tarball(tmp_path / "colors-js-1.4.1.tgz")
    report = _analyze(MasterBinaryExtractor().extract_all(str(path), path.name))

    assert {"T1195.002", "T1059.007", "T1105"} <= _technique_ids(report)
    supply_chain = next(t for t in report.mitre_mapping if t.technique_id == "T1195.002")
    assert "postinstall" in supply_chain.evidence
    assert report.attribution.suspected_package == "colors-js"


def test_archive_yara_rule_targets_unpacked_contents(tmp_path: Path) -> None:
    path = make_wheel(tmp_path / "pkg.whl")
    features = MasterBinaryExtractor().extract_all(str(path), path.name)
    rules = _rules(features, _analyze(features))

    # The strings live inside the compressed archive, so the rule must not
    # carry container-level guards and must say what to scan.
    assert "uint16(0)" not in rules.yara_rule
    assert "filesize <" not in rules.yara_rule
    assert "unpacked" in rules.yara_rule
    assert "http://185.220.101.7/drop/stage2.bin" in rules.yara_rule


# ── Heuristic detection engineer ─────────────────────────────

def test_yara_rule_targets_injected_iocs(write_sample) -> None:
    features = _features(write_sample, "dropper.py", MALICIOUS_PYTHON)
    rules = _rules(features, _analyze(features))

    assert rules.engine == "heuristic"
    assert rules.yara_rule.startswith("rule OriginTrace_")
    assert "http://185.220.101.7/drop/stage2.bin" in rules.yara_rule
    assert features["metadata"]["sha256"] in rules.yara_rule
    assert rules.yara_rule.count("{") == rules.yara_rule.count("}")


def test_yara_rule_compiles_and_matches_sample(write_sample) -> None:
    yara = pytest.importorskip("yara")
    features = _features(write_sample, "dropper.py", MALICIOUS_PYTHON)
    rules = _rules(features, _analyze(features))

    compiled = yara.compile(source=rules.yara_rule)
    assert compiled.match(data=MALICIOUS_PYTHON.encode())
    assert not compiled.match(data=BENIGN_PYTHON.encode())


def test_yara_rule_escapes_hostile_strings() -> None:
    yara = pytest.importorskip("yara")
    hostile = 'cmd /c "echo \\"pwn\\" > C:\\Temp\\x.txt"'
    rule = build_yara_rule(
        filename='we"ird\\name.exe',
        sha256="c" * 64,
        file_type="pe",
        size=4096,
        indicators=[hostile, "http://c2.example/gate.php"],
        legitimate_baseline=[],
        threat_level="High",
    )
    yara.compile(source=rule)


def test_yara_rule_excludes_legitimate_baseline() -> None:
    rule = build_yara_rule(
        filename="pkg.py",
        sha256="d" * 64,
        file_type="script",
        size=100,
        indicators=["requests.get(legit)", "http://c2.example/gate.php"],
        legitimate_baseline=["requests.get(legit)"],
        threat_level="Medium",
    )
    assert "requests.get(legit)" not in rule
    assert "http://c2.example/gate.php" in rule


def test_yara_rule_without_indicators_pins_the_hash() -> None:
    yara = pytest.importorskip("yara")
    rule = build_yara_rule(
        filename="quiet.bin",
        sha256="e" * 64,
        file_type="unknown",
        size=2048,
        indicators=[],
        legitimate_baseline=[],
        threat_level="Low",
    )
    assert "hash.sha256(0, filesize)" in rule
    yara.compile(source=rule)


def test_sigma_rule_is_valid_yaml(write_sample) -> None:
    yaml = pytest.importorskip("yaml")
    features = _features(write_sample, "install.sh", REVERSE_SHELL)
    report = _analyze(features)
    rules = _rules(features, report)

    doc = yaml.safe_load(rules.sigma_rule)
    assert doc["title"]
    uuid.UUID(doc["id"])
    assert doc["logsource"]["category"] == "process_creation"
    assert doc["logsource"]["product"] == "linux"
    assert doc["detection"]["condition"] == "selection"
    assert doc["detection"]["selection"]
    assert doc["level"] == "high"
    assert "attack.t1059.004" in doc["tags"]


def test_sigma_rule_quotes_hostile_values() -> None:
    yaml = pytest.importorskip("yaml")
    sigma = build_sigma_rule(
        filename="it's: a #trap.ps1",
        sha256="f" * 64,
        file_type="script",
        language="powershell",
        indicators=["powershell -enc 'AAAA'", "key: value # not a comment"],
        mitre_mapping=[{"tactic": "Execution", "technique_id": "T1059.001"}],
        threat_level="Medium",
    )
    doc = yaml.safe_load(sigma)
    values = doc["detection"]["selection"]["CommandLine|contains"]
    assert "powershell -enc 'AAAA'" in values
    assert "key: value # not a comment" in values
    assert doc["logsource"]["product"] == "windows"


# ── Gemini-backed agents (fake client, no network) ───────────

class _FakeModels:
    def __init__(self, response: Any = None, delay: float = 0.0) -> None:
        self.response = response
        self.delay = delay
        self.calls: list[dict[str, Any]] = []

    async def generate_content(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.response


def _fake_client(models: _FakeModels) -> Any:
    return SimpleNamespace(aio=SimpleNamespace(models=models))


ANALYST_JSON = """{
  "behavioral_summary": "Downloads and executes a second stage.",
  "threat_level": "high",
  "threat_score": 91,
  "mitre_mapping": [
    {"tactic": "Execution", "technique_id": "T1059.006",
     "technique_name": "Python", "evidence": "exec(base64.b64decode(PAYLOAD))"}
  ],
  "provenance_explanation": "No library baseline matched.",
  "suspected_ecosystem": "",
  "suspected_package": ""
}"""


def test_llm_analyst_parses_structured_response(write_sample) -> None:
    pytest.importorskip("google.genai")
    from agents.analyst import ThreatAnalystAgent

    models = _FakeModels(SimpleNamespace(text=ANALYST_JSON, parsed=None))
    agent = ThreatAnalystAgent(api_key="test-key", client=_fake_client(models))
    features = _features(write_sample, "dropper.py", MALICIOUS_PYTHON)

    report = asyncio.run(agent.analyze(features))

    assert isinstance(report, AnalystReport)
    assert report.engine == "gemini"
    assert report.threat_level == "High"
    assert report.threat_score == 91
    assert report.mitre_mapping[0].technique_id == "T1059.006"
    # Empty LLM attribution falls back to the deterministic provenance result.
    assert report.attribution.ecosystem != ""
    call = models.calls[0]
    assert call["config"].system_instruction
    assert "untrusted" in call["config"].system_instruction.lower()
    assert "dropper.py" in call["contents"]


def test_llm_analyst_rejects_empty_response() -> None:
    pytest.importorskip("google.genai")
    from agents.analyst import ThreatAnalystAgent
    from agents.llm import LLMResponseError

    models = _FakeModels(SimpleNamespace(text=None, parsed=None, candidates=[], prompt_feedback=None))
    agent = ThreatAnalystAgent(api_key="test-key", client=_fake_client(models))

    with pytest.raises(LLMResponseError):
        asyncio.run(agent.analyze({"metadata": {"filename": "x"}, "provenance": {}}))


def test_llm_analyst_times_out() -> None:
    pytest.importorskip("google.genai")
    from agents.analyst import ThreatAnalystAgent
    from agents.llm import LLMResponseError

    models = _FakeModels(SimpleNamespace(text=ANALYST_JSON, parsed=None), delay=5)
    agent = ThreatAnalystAgent(api_key="test-key", client=_fake_client(models), timeout_s=0.05)

    with pytest.raises(LLMResponseError, match="timed out"):
        asyncio.run(agent.analyze({"metadata": {"filename": "x"}, "provenance": {}}))


def test_llm_detection_engineer_parses_rules() -> None:
    pytest.importorskip("google.genai")
    from agents.detection_engineer import DetectionEngineerAgent

    payload = '{"yara_rule": "rule X { condition: true }", "sigma_rule": "title: X"}'
    models = _FakeModels(SimpleNamespace(text=payload, parsed=None))
    agent = DetectionEngineerAgent(api_key="test-key", client=_fake_client(models))

    rules = asyncio.run(agent.generate_rules(malware_context={"provenance": {}}, analyst_report={}))

    assert isinstance(rules, DetectionArtifacts)
    assert rules.engine == "gemini"
    assert rules.yara_rule.startswith("rule X")
