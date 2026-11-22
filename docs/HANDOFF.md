# Handoff
_Updated by the last agent session. Keep under 40 lines._

## Current state
- Branch `feature/semantic-lifting-gcp`. Backend + frontend work end to end locally without an API key.
- Backend: `pytest` green (75 tests on the pinned stack, Python 3.11). Frontend: `npm test` (11), `typecheck`, `lint`, `build` green.
- Pipeline modes: `llm` (Gemini, falls back to heuristics), `heuristic` (offline rules), `mock` (`USE_MOCK=true`). See README "Running Locally".
- One API contract: `models.py` `FinalReport` <-> `frontend/src/types/report.ts`. Change both together.

## What changed last session (2026-11-21)
- Fixed prod-breaking bug: `UploadFile` was read inside the SSE generator; on fastapi 0.111 every upload failed with "I/O operation on closed file". Upload is now spooled in the handler (`main._spool_upload`), 32 MB limit.
- `main.py`: `create_app()`, mode resolution, `ALLOWED_ORIGINS` honoured, readable error/timeout events, heuristic fallback.
- New `agents/heuristic.py` (ATT&CK rule table, YARA/Sigma builders), `agents/llm.py`, `agents/context.py`.
- Extractors: shared `extractors/ioc.py`, magic-byte routing first, string-scan fallback without radare2, optional deps degrade instead of crashing, provenance has a lexical fallback.
- Concolic engine: was dead (wrong image base on x64, `rcx` crash on x86, thread timeout that could not cancel). Now child-process with hard kill; verified on real PEs.
- `requirements.txt`: pinned `bitstring==4.4.0`, `pycparser==2.23` (angr 9.2.125 does not import with their new majors), `google-genai==1.16.1` (1.16.0 was yanked).
- Frontend: `/app` is now the Investigation Workbench (was unrouted, imports broken); old dashboard at `/classic`. Shared SSE client `src/lib/analyzeStream.ts` buffers chunks (large reports used to be dropped). Removed fabricated fallback findings and an XSS sink (`dangerouslySetInnerHTML` on rule text).
- Removed duplicate `mock_api/main.py`, `mock_api/models.py`.

## Next steps
- Deploy and smoke-test on Cloud Run: Dockerfile model pre-download step and the `cloudbuild.yaml` `^@^` env delimiter were changed but not built here.
- radare2/r2ghidra paths (`_extract_pe_with_r2`, ELF r2) are untested locally (no r2 on Windows); verify in the container.
- Gemini agents are tested with a fake client only; run one real `llm` analysis with a key.
- Archive unpacking (.whl/.tgz/.zip) is not implemented; docs now say so.

## Open questions / gotchas
- `extractors/pe_extractor.py` and `mock_dropper.py` are unused legacy files; delete or keep?
- Heuristic rules are regex-based: a file that only mentions `eval()` in a docstring can score Medium.
- `.venv` on the Windows box was repaired to a uv-managed Python 3.12 with newer, unpinned packages; the pinned stack is the source of truth.
- `graphify-out/GRAPH_REPORT.md` + `graph.json` are committed; rebuild with `/graphify . --update` after large changes.
