# OriginTrace

**Autonomous Semantic Provenance (ASP)**

## The Narrative
OriginTrace is the technical forensic engine under the ResilAI ecosystem. While ResilAI handles high-level risk and governance, OriginTrace is the "hard-hat" tool that identifies malicious code-level discrepancies (deltas) in hijacked libraries.

## The Supply Chain Pivot
Traditional security relies on reactive detection—flagging a threat only after it has executed or matched a known signature. OriginTrace shifts the paradigm from **reactive detection** to **autonomous attribution**. We dissect software supply chain components at a fundamental level, automatically identifying where malicious modifications were introduced, prioritizing the source and lineage of the code block before it deploys.

## Autonomous Semantic Provenance (ASP)
We are defining a new category of cybersecurity: **Autonomous Semantic Provenance (ASP)**.
ASP goes beyond static and dynamic analysis. It understands the *meaning* (semantics) of code changes and autonomously traces the *origin* (provenance) of those changes. By analyzing behavioral features, AST deltas, and cross-referencing global threat intelligence, OriginTrace maps behaviors to MITRE ATT&CK techniques and isolates hijacked elements from native code with unprecedented accuracy.

## Competitive Advantage
OriginTrace is built for the modern threat landscape, offering distinct advantages over traditional tools:

* **vs. Ghidra**: **Speed.** Manual reverse engineering in Ghidra can take days or weeks for a skilled analyst. OriginTrace automates this workflow, delivering deep code analysis and behavioral parsing in a fraction of the time.
* **vs. CAPA**: **Provenance Context.** While CAPA is excellent for identifying capabilities, it lacks historical and contextual awareness. OriginTrace provides the full provenance—not just *what* the code does, but *where* it came from and *how* it was altered.
* **vs. VirusTotal (VT)**: **The "Why".** VT tells you *if* a file is bad based on community consensus and antivirus engines. OriginTrace tells you *why* it's bad, providing the underlying semantic reasoning, the specific malicious deltas, and the precise context needed to write robust detection engineering rules.

## Ecosystem Architecture: OriginTrace vs. ResilAI
To prevent brand confusion, it is critical to understand the distinction between our core offerings:

* **OriginTrace**: The **Technical Engine**. The hard-hat forensic tool for SOC analysts and detection engineers. It performs the deep code-level analysis, binary inspection, and logic tracing.
* **ResilAI**: The **Governance Layer**. The executive dashboard for CISOs and risk managers. It consumes intelligence from OriginTrace to quantify business risk, ensure compliance, and orchestrate automated policy enforcement.

## Running Locally

**Backend** (FastAPI, Python 3.11 to match the Docker image):

```bash
pip install -r requirements.txt
uvicorn main:app --port 8080
```

The heavy tools are optional. Without radare2, angr, libmagic or FAISS the pipeline still runs and degrades to pure-Python analysis; `GET /health` lists what is available. A light install is enough for development:

```bash
pip install fastapi==0.111.0 "uvicorn[standard]==0.30.1" pydantic==2.8.2 python-multipart==0.0.9 pefile==2023.2.7 pyelftools==0.31 oletools==0.60.2
```

**Frontend** (Vite + React, expects the API on `http://localhost:8080` unless `VITE_API_URL` is set):

```bash
cd frontend && npm install && npm run dev
```

Open `http://localhost:5173/app` for the Investigation Workbench (`/classic` keeps the single-page dashboard).

Accepted uploads: packages (PyPI wheels and sdists, npm tarballs, zip, tar), PE and ELF binaries, scripts (Python, JavaScript, shell, PowerShell, batch) and Office documents, up to 32 MB. Packages are unpacked in memory with strict limits; install hooks are analysed first.

### Pipeline modes

| Mode | When | Analysis and rules come from |
| --- | --- | --- |
| `llm` | `GEMINI_API_KEY` is set | Gemini, with automatic fallback to heuristics if a call fails |
| `heuristic` | no API key | Offline rule engine (`agents/heuristic.py`), deterministic |
| `mock` | `USE_MOCK=true` | Canned demo data; only the file hashes are real |

`ORIGINTRACE_MODE` forces a mode. Other settings: `ALLOWED_ORIGINS` (comma-separated CORS origins), `MAX_UPLOAD_MB` (default 32), `EXTRACTION_TIMEOUT_S` (default 120), `GEMINI_MODEL`, `LLM_TIMEOUT_S`, `ORIGINTRACE_PROVENANCE` (`auto` | `faiss` | `lexical` | `off`).

### Tests

```bash
pip install -r requirements-dev.txt && pytest      # backend
cd frontend && npm test && npm run typecheck && npm run lint
```

## Brand Guidelines
When building community-contributed rules, custom integrations, or extending the Investigation Workbench, please adhere to our core color palette:

* **Resilience Cyan**: Represents verified, safe provenance, trusted libraries, clean code paths, and optimal system health.
* **Infection Crimson**: Represents malicious deltas, hijacked behaviors, identified threats, and compromised dependencies.
