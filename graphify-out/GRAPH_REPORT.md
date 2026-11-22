# Graph Report - origintrace-core  (2026-11-21)

## Corpus Check
- 67 files · ~30,427 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 10 file(s) not represented in the graph (top: (none) 5, .css 2, .cache 1)

## Summary
- 780 nodes · 1587 edges · 57 communities (38 shown, 19 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 48 edges (avg confidence: 0.91)
- Token cost: 281,118 input · 0 output

## Graph Freshness
- Built from commit: `760d4ae0`
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
- .extract
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
- Icon Sprite
- Hero Illustration
- React Logo
- heuristic.py
- test_extractors.py
- report.ts
- useInvestigationStore
- analyzeStream.ts
- analyze_features
- .extract_all
- detect_file_type
- scan_file_for_iocs
- MacroExtractor
- build_yara_rule
- AttributionGraphPane.tsx
- context.py
- re
- MalwareSummaryPane.tsx
- script_extractor.py
- get_capabilities
- IntelligenceRibbon.tsx
- AnalysisDashboard.tsx
- find_iocs
- _classify_by_header
- ._decompile_at_seek
- AGENTS.md

## God Nodes (most connected - your core abstractions)
1. `MasterBinaryExtractor` - 25 edges
2. `create_app()` - 25 edges
3. `useInvestigationStore` - 20 edges
4. `ScriptExtractor` - 18 edges
5. `AnalystReport` - 18 edges
6. `compilerOptions` - 17 edges
7. `compilerOptions` - 16 edges
8. `DetectionArtifacts` - 15 edges
9. `_upload()` - 15 edges
10. `requirements.txt (Python Dependencies)` - 15 edges

## Surprising Connections (you probably didn't know these)
- `What changed last session (2026-11-21)` --references--> `create_app()`  [INFERRED]
  docs/HANDOFF.md → main.py
- `What changed last session (2026-11-21)` --references--> `_spool_upload()`  [INFERRED]
  docs/HANDOFF.md → main.py
- `DetectionEngineerAgent` --uses--> `DetectionArtifacts`  [INFERRED]
  agents/detection_engineer.py → models.py
- `test_llm_analyst_rejects_empty_response()` --uses--> `LLMResponseError`  [INFERRED]
  tests/test_agents.py → agents/llm.py
- `test_llm_analyst_times_out()` --uses--> `LLMResponseError`  [INFERRED]
  tests/test_agents.py → agents/llm.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Semantic Embedding and Retrieval Stack** — requirements_faiss_cpu, requirements_sentence_transformers, requirements_numpy, requirements_google_genai [INFERRED 0.75]
- **Binary and File-Format Analysis Toolchain** — requirements_pefile, requirements_r2pipe, requirements_angr, requirements_pyelftools, requirements_oletools, requirements_python_magic [INFERRED 0.85]
- **Vite + React starter template default assets** — frontend_public_favicon, frontend_public_icons, frontend_src_assets_hero, frontend_src_assets_react, frontend_src_assets_vite [INFERRED 0.85]

## Communities (57 total, 19 thin omitted)

### Community 0 - "analyst.py"
Cohesion: 0.08
Nodes (14): LLMAnalystReport, LLMMitreTechnique, build_llm_context(), DetectionEngineerAgent, LLMDetectionArtifacts, _strip_code_fence(), default_model(), default_timeout() (+6 more)

### Community 1 - "App.tsx"
Cohesion: 0.23
Nodes (10): frontend/index.html (Vite HTML Entry), AnalysisDashboard, App(), PageLoading(), WorkbenchPage, Layout(), DocsPage(), LandingPage() (+2 more)

### Community 2 - "extractor.py"
Cohesion: 0.13
Nodes (4): is_ioc(), current_seek(), open_r2(), r2_available()

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
Nodes (8): _get_resolve_with_timeout(), _child_entry(), ConcolicEngine, resolve_with_timeout(), _run_engine(), run_with_hard_timeout(), test_hard_timeout_kills_runaway_worker(), test_hard_timeout_returns_worker_result()

### Community 7 - ".extract"
Cohesion: 0.18
Nodes (3): _detect_language(), _read_text(), _unique()

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
Cohesion: 0.07
Nodes (38): ThreatAnalystAgent, HeuristicAnalystAgent, HeuristicDetectionEngineerAgent, build_engines(), BinaryExtractor, _default_delay(), DetectionEngineerAgent, ThreatAnalystAgent (+30 more)

### Community 13 - "ESLint Config"
Cohesion: 0.15
Nodes (12): eslint@^10.2.1, @eslint/js@^10.0.1, eslint-plugin-react-hooks@^7.1.1, eslint-plugin-react-refresh@^0.5.2, globals@^17.5.0, typescript-eslint@^8.58.2, eslint, @eslint/js (+4 more)

### Community 14 - "Frontend Dev Deps"
Cohesion: 0.13
Nodes (15): devDependencies, autoprefixer@^10.5.0, postcss@^8.5.14, tailwindcss@^3.4.19, @types/node@^24.12.2, @types/react@^19.2.14, @types/react-dom@^19.2.3, typescript@~6.0.2 (+7 more)

### Community 15 - "main.py"
Cohesion: 0.06
Nodes (20): Current state, Handoff, Next steps, Open questions / gotchas, What changed last session (2026-11-21), allowed_origins(), analyze_binary(), _describe() (+12 more)

### Community 16 - "React + TypeScript + Vite"
Cohesion: 0.50
Nodes (3): Expanding the ESLint configuration, React Compiler, React + TypeScript + Vite

### Community 17 - "test_api.py"
Cohesion: 0.10
Nodes (29): create_app(), Engines, resolve_mode(), FinalReport, _BrokenExtractor, _engines(), _events(), _FailingAgent (+21 more)

### Community 18 - "Cloud Build Pipeline"
Cohesion: 0.33
Nodes (5): images, steps, args, entrypoint, name

### Community 19 - "Vite Build Config"
Cohesion: 0.40
Nodes (4): vite@^8.0.10, @vitejs/plugin-react@^6.0.1, vite, @vitejs/plugin-react

### Community 20 - "NPM Scripts"
Cohesion: 0.29
Nodes (7): scripts, build, dev, lint, preview, test, typecheck

### Community 31 - "heuristic.py"
Cohesion: 0.15
Nodes (13): attribution_from_provenance(), _autoexec_macro(), _clip(), _has_macros(), IndicatorView, _masquerade(), _obfuscation(), _p() (+5 more)

### Community 32 - "test_extractors.py"
Cohesion: 0.18
Nodes (16): MasterBinaryExtractor, ScriptExtractor, ExtractionResult, test_duplicate_long_blobs_are_reported_once(), test_extract_all_flags_extension_mismatch(), test_extract_all_pe_falls_back_to_string_scan(), test_extract_all_scans_plain_text_with_unknown_extension(), test_extract_all_script_matches_schema() (+8 more)

### Community 33 - "report.ts"
Cohesion: 0.11
Nodes (18): GraphLink, GraphLinkData, GraphNode, GraphNodeData, ThreatGraphProps, InvestigationState, AnalystReport, Attribution (+10 more)

### Community 34 - "useInvestigationStore"
Cohesion: 0.22
Nodes (12): Command, CommandPalette(), AgentTimeline(), MalwareDropzone(), runAnalysis(), WorkbenchPage(), AgentStep, AgentStepStatus (+4 more)

### Community 35 - "analyzeStream.ts"
Cohesion: 0.18
Nodes (10): AnalysisError, analyzeFile(), AnalyzeOptions, apiBaseUrl(), describeHttpError(), isAbort(), isStreamEvent(), MAX_UPLOAD_BYTES (+2 more)

### Community 36 - "analyze_features"
Cohesion: 0.24
Nodes (7): analyze_features(), build_sigma_rule(), _sigma_indicators(), _sigma_product(), _strings(), _today(), _unique()

### Community 38 - "detect_file_type"
Cohesion: 0.19
Nodes (9): detect_file_type(), _looks_like_text(), _ooxml(), test_detect_file_type(), test_language_detection_without_extension(), test_macro_extractor_handles_macro_free_ooxml(), test_magic_bytes_beat_a_misleading_extension(), test_ooxml_zip_is_an_office_document() (+1 more)

### Community 39 - "scan_file_for_iocs"
Cohesion: 0.22
Nodes (3): ELFExtractor, iter_printable_strings(), scan_file_for_iocs()

### Community 40 - "MacroExtractor"
Cohesion: 0.18
Nodes (4): _embedded_ole_objects(), MacroExtractor, scan_macro_source(), test_scan_macro_source_flags_autoexec_and_urls()

### Community 41 - "build_yara_rule"
Cohesion: 0.20
Nodes (6): build_yara_rule(), _is_strong_indicator(), _is_weak_indicator(), _yara_escape(), _yara_rule_name(), test_yara_rule_excludes_legitimate_baseline()

### Community 42 - "AttributionGraphPane.tsx"
Cohesion: 0.24
Nodes (8): buildGraph(), IndicatorNode(), IndicatorNodeData, KIND_STYLE, KindIcon(), NodeKind, nodeTypes, truncateEnd()

### Community 43 - "context.py"
Cohesion: 0.29
Nodes (3): level_from_score(), normalize_threat_level(), score_from_level()

### Community 45 - "MalwareSummaryPane.tsx"
Cohesion: 0.36
Nodes (7): collectIndicators(), fileKind(), Indicator, MalwareSummaryPane(), SUSPECT_APIS, Typewriter(), ExtractionResult

### Community 47 - "get_capabilities"
Cohesion: 0.29
Nodes (5): get_capabilities(), _load_magic(), _module_available(), _capabilities(), test_capabilities_report_booleans()

### Community 48 - "IntelligenceRibbon.tsx"
Cohesion: 0.57
Nodes (5): engineLabel(), IntelligenceRibbon(), scoreColor(), formatBytes(), truncateMiddle()

### Community 49 - "AnalysisDashboard.tsx"
Cohesion: 0.53
Nodes (4): AnalysisDashboard(), AnalysisState, ThreatGraph(), copyText()

### Community 50 - "find_iocs"
Cohesion: 0.40
Nodes (4): find_iocs(), test_find_iocs_extracts_network_and_host_indicators(), test_find_iocs_is_ordered_and_unique(), test_find_iocs_rejects_invalid_ipv4()

## Knowledge Gaps
- **20 isolated node(s):** `frontend/index.html (Vite HTML Entry)`, `Favicon (purple Vite lightning-bolt mark)`, `Vite logo (lightning bolt in parentheses)`, `SVG icon sprite (bluesky, discord, documentation, github, social, x symbols)`, `Hero illustration (isometric stacked rounded slabs, purple base layer)` (+15 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 297 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **19 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MasterBinaryExtractor` connect `test_extractors.py` to `extractor.py`, `.extract_all`, `scan_file_for_iocs`, `MacroExtractor`, `test_agents.py`, `main.py`, `test_api.py`, `._decompile_at_seek`?**
  _High betweenness centrality (0.040) - this node is a cross-community bridge._
- **Are the 3 inferred relationships involving `MasterBinaryExtractor` (e.g. with `ELFExtractor` and `MacroExtractor`) actually correct?**
  _`MasterBinaryExtractor` has 3 INFERRED edges - model-reasoned connections that need verification._
- **What connects `frontend/index.html (Vite HTML Entry)`, `Favicon (purple Vite lightning-bolt mark)`, `Vite logo (lightning bolt in parentheses)` to the rest of the system?**
  _20 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `analyst.py` be split into smaller, more focused modules?**
  _Cohesion score 0.080338266384778 - nodes in this community are weakly interconnected._
- **Why does `react` connect `App.tsx` to `report.ts`, `useInvestigationStore`, `Frontend Runtime Deps`, `AttributionGraphPane.tsx`, `DetectionEngineeringPane.tsx`, `MalwareSummaryPane.tsx`, `IntelligenceRibbon.tsx`, `AnalysisDashboard.tsx`?**
  _High betweenness centrality (0.021) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `create_app()` (e.g. with `What changed last session (2026-11-21)` and `lifespan()`) actually correct?**
  _`create_app()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Should `extractor.py` be split into smaller, more focused modules?**
  _Cohesion score 0.1339031339031339 - nodes in this community are weakly interconnected._