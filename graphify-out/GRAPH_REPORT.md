# Graph Report - origintrace-core  (2026-11-22)

## Corpus Check
- 69 files · ~34,804 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 10 file(s) not represented in the graph (top: (none) 5, .css 2, .cache 1)

## Summary
- 912 nodes · 1871 edges · 56 communities (39 shown, 17 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 51 edges (avg confidence: 0.91)
- Token cost: 281,118 input · 0 output

## Graph Freshness
- Built from commit: `dc8f7111`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- analyst.py
- App.tsx
- extractor.py
- Product Concepts (README)
- provenance.py
- Frontend Deps Snapshot
- symbolic_resolver.py
- script_extractor.py
- Frontend Runtime Deps
- TS App Config
- TS Node Config
- DetectionEngineeringPane.tsx
- test_agents.py
- ESLint Config
- Frontend Dev Deps
- main.py
- React + TypeScript + Vite
- test_api.py
- Cloud Build Pipeline
- Vite Build Config
- NPM Scripts
- TS Root Config
- Deploy Script
- Vite Logos
- archive_extractor.py
- Icon Sprite
- Hero Illustration
- React Logo
- heuristic.py
- test_extractors.py
- report.ts
- useInvestigationStore
- analyzeStream.ts
- with
- MasterBinaryExtractor
- detect_file_type
- scan_file_for_iocs
- MacroExtractor
- mock_agents.py
- AttributionGraphPane.tsx
- _event_stream
- re
- MalwareSummaryPane.tsx
- os
- mock_dropper.py
- IntelligenceRibbon.tsx
- Handoff
- AGENTS.md

## God Nodes (most connected - your core abstractions)
1. `MasterBinaryExtractor` - 29 edges
2. `create_app()` - 25 edges
3. `ScriptExtractor` - 20 edges
4. `useInvestigationStore` - 20 edges
5. `IndicatorView` - 18 edges
6. `AnalystReport` - 18 edges
7. `_analyze()` - 18 edges
8. `compilerOptions` - 17 edges
9. `_upload()` - 16 edges
10. `compilerOptions` - 16 edges

## Surprising Connections (you probably didn't know these)
- `What changed last session (2026-11-21)` --references--> `_spool_upload()`  [INFERRED]
  docs/HANDOFF.md → main.py
- `What changed last session (2026-11-21)` --references--> `create_app()`  [INFERRED]
  docs/HANDOFF.md → main.py
- `HeuristicAnalystAgent` --uses--> `AnalystReport`  [INFERRED]
  agents/heuristic.py → models.py
- `HeuristicDetectionEngineerAgent` --uses--> `DetectionArtifacts`  [INFERRED]
  agents/heuristic.py → models.py
- `ThreatAnalystAgent` --uses--> `MitreTechnique`  [INFERRED]
  agents/analyst.py → models.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Semantic Embedding and Retrieval Stack** — requirements_faiss_cpu, requirements_sentence_transformers, requirements_numpy, requirements_google_genai [INFERRED 0.75]
- **Binary and File-Format Analysis Toolchain** — requirements_pefile, requirements_r2pipe, requirements_angr, requirements_pyelftools, requirements_oletools, requirements_python_magic [INFERRED 0.85]
- **Vite + React starter template default assets** — frontend_public_favicon, frontend_public_icons, frontend_src_assets_hero, frontend_src_assets_react, frontend_src_assets_vite [INFERRED 0.85]

## Communities (56 total, 17 thin omitted)

### Community 0 - "analyst.py"
Cohesion: 0.05
Nodes (23): LLMAnalystReport, LLMMitreTechnique, build_llm_context(), level_from_score(), normalize_threat_level(), score_from_level(), DetectionEngineerAgent, LLMDetectionArtifacts (+15 more)

### Community 1 - "App.tsx"
Cohesion: 0.23
Nodes (10): frontend/index.html (Vite HTML Entry), AnalysisDashboard, App(), PageLoading(), WorkbenchPage, Layout(), DocsPage(), LandingPage() (+2 more)

### Community 2 - "extractor.py"
Cohesion: 0.08
Nodes (14): _classify_by_header(), get_capabilities(), _get_resolve_with_timeout(), _has_obfuscation_markers(), _is_ooxml(), _load_magic(), _looks_like_text(), _module_available() (+6 more)

### Community 3 - "Product Concepts (README)"
Cohesion: 0.08
Nodes (25): Autonomous Semantic Provenance (ASP), Brand Guidelines, Competitive Advantage, Ecosystem Architecture: OriginTrace vs. ResilAI, OriginTrace, Pipeline modes, Running Locally, Tests (+17 more)

### Community 4 - "provenance.py"
Cohesion: 0.12
Nodes (8): _empty_result(), get_provenance_engine(), LexicalProvenanceEngine, _matched_result(), _native_result(), ProvenanceEngine, test_lexical_provenance_matches_hijacked_library(), test_lexical_provenance_native_and_empty_inputs()

### Community 5 - "Frontend Deps Snapshot"
Cohesion: 0.13
Nodes (22): dependencies, clsx@^2.1.0, framer-motion@^11.0.0, lucide-react@^0.344.0, react-resizable-panels@^2.0.0, reactflow@^11.10.0, tailwind-merge@^2.2.0, zustand@^4.5.0 (+14 more)

### Community 6 - "symbolic_resolver.py"
Cohesion: 0.10
Nodes (6): _child_entry(), ConcolicEngine, _run_engine(), run_with_hard_timeout(), test_hard_timeout_kills_runaway_worker(), test_hard_timeout_returns_worker_result()

### Community 7 - "script_extractor.py"
Cohesion: 0.12
Nodes (6): _detect_language(), _parse_python(), _python_dynamic_calls(), _read_text(), _shannon_entropy(), _unique()

### Community 8 - "Frontend Runtime Deps"
Cohesion: 0.10
Nodes (25): dependencies, clsx@^2.1.0, framer-motion@^11.18.2, lucide-react@^0.344.0, react@^19.2.5, react-dom@^19.2.5, react-force-graph-2d@^1.29.1, react-resizable-panels@^2.0.0 (+17 more)

### Community 9 - "TS App Config"
Cohesion: 0.11
Nodes (18): compilerOptions, allowImportingTsExtensions, erasableSyntaxOnly, jsx, lib, module, moduleDetection, moduleResolution (+10 more)

### Community 10 - "TS Node Config"
Cohesion: 0.11
Nodes (17): compilerOptions, allowImportingTsExtensions, erasableSyntaxOnly, lib, module, moduleDetection, moduleResolution, noEmit (+9 more)

### Community 11 - "DetectionEngineeringPane.tsx"
Cohesion: 0.21
Nodes (10): CustomResizeHandle(), InvestigationWorkbench(), AttributionGraphPane(), DetectionEngineeringPane(), highlight(), RuleKind, TOKEN_CLASS, MitreAttackPane() (+2 more)

### Community 12 - "test_agents.py"
Cohesion: 0.14
Nodes (27): ThreatAnalystAgent, AnalystReport, make_wheel(), _analyze(), _fake_client(), _FakeModels, _features(), _rules() (+19 more)

### Community 13 - "ESLint Config"
Cohesion: 0.15
Nodes (12): eslint@^10.2.1, @eslint/js@^10.0.1, eslint-plugin-react-hooks@^7.1.1, eslint-plugin-react-refresh@^0.5.2, globals@^17.5.0, typescript-eslint@^8.58.2, eslint, @eslint/js (+4 more)

### Community 14 - "Frontend Dev Deps"
Cohesion: 0.13
Nodes (15): devDependencies, autoprefixer@^10.5.0, postcss@^8.5.14, tailwindcss@^3.4.19, @types/node@^24.12.2, @types/react@^19.2.14, @types/react-dom@^19.2.3, typescript@~6.0.2 (+7 more)

### Community 15 - "main.py"
Cohesion: 0.15
Nodes (4): allowed_origins(), build_engines(), Engines, _env_float()

### Community 16 - "React + TypeScript + Vite"
Cohesion: 0.50
Nodes (3): Expanding the ESLint configuration, React Compiler, React + TypeScript + Vite

### Community 17 - "test_api.py"
Cohesion: 0.09
Nodes (31): HeuristicAnalystAgent, HeuristicDetectionEngineerAgent, create_app(), resolve_mode(), FinalReport, _BrokenExtractor, _engines(), _events() (+23 more)

### Community 18 - "Cloud Build Pipeline"
Cohesion: 0.33
Nodes (5): images, steps, args, entrypoint, name

### Community 19 - "Vite Build Config"
Cohesion: 0.40
Nodes (4): vite@^8.0.10, @vitejs/plugin-react@^6.0.1, vite, @vitejs/plugin-react

### Community 20 - "NPM Scripts"
Cohesion: 0.29
Nodes (7): scripts, build, dev, lint, preview, test, typecheck

### Community 26 - "archive_extractor.py"
Cohesion: 0.05
Nodes (20): ArchiveExtractor, _base(), _depth(), _display_path(), _Entry, _ext(), _find_metadata(), _GzipBackend (+12 more)

### Community 31 - "heuristic.py"
Cohesion: 0.06
Nodes (33): attribution_from_provenance(), analyze_features(), attribution_for(), _autoexec_macro(), build_sigma_rule(), build_yara_rule(), _clip(), _has_macros() (+25 more)

### Community 32 - "test_extractors.py"
Cohesion: 0.15
Nodes (16): find_iocs(), ScriptExtractor, test_detect_file_type(), test_duplicate_long_blobs_are_reported_once(), test_find_iocs_extracts_network_and_host_indicators(), test_find_iocs_is_ordered_and_unique(), test_find_iocs_rejects_invalid_ipv4(), test_javascript_imports_and_calls() (+8 more)

### Community 33 - "report.ts"
Cohesion: 0.09
Nodes (21): GraphLink, GraphLinkData, GraphNode, GraphNodeData, ThreatGraphProps, InvestigationState, AnalystReport, ArchiveFeatures (+13 more)

### Community 34 - "useInvestigationStore"
Cohesion: 0.22
Nodes (12): Command, CommandPalette(), AgentTimeline(), MalwareDropzone(), runAnalysis(), WorkbenchPage(), AgentStep, AgentStepStatus (+4 more)

### Community 35 - "analyzeStream.ts"
Cohesion: 0.18
Nodes (10): AnalysisError, analyzeFile(), AnalyzeOptions, apiBaseUrl(), describeHttpError(), isAbort(), isStreamEvent(), MAX_UPLOAD_BYTES (+2 more)

### Community 36 - "with"
Cohesion: 0.07
Nodes (30): name, runs-on, steps, concurrency, cancel-in-progress, group, run, defaults (+22 more)

### Community 37 - "MasterBinaryExtractor"
Cohesion: 0.10
Nodes (10): _compute_hashes(), MasterBinaryExtractor, scan_file_for_iocs(), lifespan(), ExtractionResult, test_extract_all_flags_extension_mismatch(), test_extract_all_pe_falls_back_to_string_scan(), test_extract_all_scans_plain_text_with_unknown_extension() (+2 more)

### Community 38 - "detect_file_type"
Cohesion: 0.22
Nodes (13): detect_file_type(), _archive(), _ooxml(), test_archive_member_limit_is_enforced(), test_archive_member_temp_files_are_removed(), test_archives_are_detected(), test_magic_bytes_beat_a_misleading_extension(), test_npm_tarball_reports_install_hooks() (+5 more)

### Community 40 - "MacroExtractor"
Cohesion: 0.18
Nodes (5): _embedded_ole_objects(), MacroExtractor, scan_macro_source(), test_macro_extractor_handles_macro_free_ooxml(), test_scan_macro_source_flags_autoexec_and_urls()

### Community 41 - "mock_agents.py"
Cohesion: 0.17
Nodes (5): BinaryExtractor, _default_delay(), DetectionEngineerAgent, ThreatAnalystAgent, MitreTechnique

### Community 42 - "AttributionGraphPane.tsx"
Cohesion: 0.24
Nodes (8): buildGraph(), IndicatorNode(), IndicatorNodeData, KIND_STYLE, KindIcon(), NodeKind, nodeTypes, truncateEnd()

### Community 43 - "_event_stream"
Cohesion: 0.25
Nodes (7): _describe(), _dump(), _error(), _event_stream(), _extraction_summary(), _sse(), _status()

### Community 44 - "re"
Cohesion: 0.25
Nodes (3): iter_printable_strings(), extract_local_features(), test_printable_strings_cover_ascii_and_utf16()

### Community 45 - "MalwareSummaryPane.tsx"
Cohesion: 0.36
Nodes (7): collectIndicators(), fileKind(), Indicator, MalwareSummaryPane(), SUSPECT_APIS, Typewriter(), ExtractionResult

### Community 46 - "os"
Cohesion: 0.25
Nodes (4): analyze_binary(), _remove(), _safe_filename(), _spool_upload()

### Community 48 - "IntelligenceRibbon.tsx"
Cohesion: 0.29
Nodes (9): AnalysisDashboard(), AnalysisState, ThreatGraph(), engineLabel(), IntelligenceRibbon(), scoreColor(), copyText(), formatBytes() (+1 more)

### Community 49 - "Handoff"
Cohesion: 0.33
Nodes (5): Current state, Handoff, Next steps, Open questions / gotchas, What changed last session (2026-11-21)

## Knowledge Gaps
- **20 isolated node(s):** `frontend/index.html (Vite HTML Entry)`, `angr`, `faiss-cpu`, `fastapi`, `google-genai` (+15 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 350 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **17 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MasterBinaryExtractor` connect `MasterBinaryExtractor` to `test_extractors.py`, `extractor.py`, `detect_file_type`, `scan_file_for_iocs`, `test_agents.py`, `main.py`, `test_api.py`, `archive_extractor.py`?**
  _High betweenness centrality (0.040) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `MasterBinaryExtractor` (e.g. with `ArchiveExtractor` and `ScriptExtractor`) actually correct?**
  _`MasterBinaryExtractor` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `frontend/index.html (Vite HTML Entry)`, `angr`, `faiss-cpu` to the rest of the system?**
  _20 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `analyst.py` be split into smaller, more focused modules?**
  _Cohesion score 0.052429667519181586 - nodes in this community are weakly interconnected._
- **Why does `react` connect `App.tsx` to `report.ts`, `useInvestigationStore`, `Frontend Runtime Deps`, `AttributionGraphPane.tsx`, `DetectionEngineeringPane.tsx`, `MalwareSummaryPane.tsx`, `IntelligenceRibbon.tsx`?**
  _High betweenness centrality (0.015) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `create_app()` (e.g. with `What changed last session (2026-11-21)` and `lifespan()`) actually correct?**
  _`create_app()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Should `extractor.py` be split into smaller, more focused modules?**
  _Cohesion score 0.07936507936507936 - nodes in this community are weakly interconnected._