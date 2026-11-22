import { Book, Code, Layers } from 'lucide-react';

export function DocsPage() {
  return (
    <div className="flex-grow bg-gray-950 text-gray-300 font-sans p-8 md:p-16">
      <div className="max-w-4xl mx-auto">
        <div className="mb-12 border-b border-gray-800 pb-8">
          <h1 className="text-4xl font-bold text-white mb-4">Documentation</h1>
          <p className="text-xl text-gray-500">Technical reference for the OriginTrace forensic engine.</p>
        </div>

        <div className="space-y-16">
          
          {/* Architecture Section */}
          <section>
            <div className="flex items-center space-x-3 mb-6">
              <Layers className="w-6 h-6 text-cyan-400" />
              <h2 className="text-2xl font-bold text-white">Architecture</h2>
            </div>
            <div className="prose prose-invert max-w-none text-gray-400">
              <p className="mb-4">
                OriginTrace runs every upload through an asynchronous three-stage pipeline:
              </p>
              <ul className="list-disc pl-6 space-y-2 mb-4">
                <li><strong>Stage 1 (Static Extraction):</strong> A file-type router inspects magic bytes and dispatches to a specialised extractor: <code className="text-cyan-300 bg-gray-900 px-1 rounded">pefile</code> / <code className="text-cyan-300 bg-gray-900 px-1 rounded">radare2</code> / <code className="text-cyan-300 bg-gray-900 px-1 rounded">angr</code> for binaries, AST and pattern analysis for scripts, <code className="text-cyan-300 bg-gray-900 px-1 rounded">oletools</code> for Office macros. Nothing is detonated.</li>
                <li><strong>Stage 2 (Threat Analysis):</strong> Extracted features are mapped to MITRE ATT&CK techniques and the supply-chain delta is explained.</li>
                <li><strong>Stage 3 (Detection Engineering):</strong> A YARA rule and a Sigma rule are generated from the injected artifacts, excluding the legitimate library baseline.</li>
              </ul>
              <p className="mb-4">
                Stages 2 and 3 use Google Gemini when an API key is configured, and a deterministic offline rule engine otherwise (or as a fallback if a Gemini call fails). Every report states which engine produced it.
              </p>
              <p>
                The frontend consumes this pipeline via Server-Sent Events (SSE) from a FastAPI backend.
              </p>
            </div>
          </section>

          {/* API Reference Section */}
          <section>
            <div className="flex items-center space-x-3 mb-6">
              <Code className="w-6 h-6 text-cyan-400" />
              <h2 className="text-2xl font-bold text-white">API Reference</h2>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-800 bg-black/50">
                <code className="text-sm font-mono text-cyan-400">POST /api/v1/analyze</code>
              </div>
              <div className="p-6 text-gray-400 text-sm">
                <p className="mb-4"><strong>Content-Type:</strong> <code className="text-gray-300 bg-gray-800 px-1 rounded">multipart/form-data</code></p>
                <p className="mb-4">Accepts a single file upload under the key <code>file</code> (max 32 MB). Oversized uploads return <code>413</code>, empty ones <code>400</code>.</p>
                <p className="mb-2"><strong>Response Stream (SSE):</strong> one JSON object per event; the stream ends with either <code>complete</code> or <code>error</code>.</p>
                <pre className="bg-black p-4 rounded text-gray-300 font-mono text-xs overflow-x-auto">
{`data: {"type": "status", "agent": "Extractor", "message": "Identifying file type..."}

data: {"type": "complete", "data": {"schema_version": "1.0", "mode": "heuristic",
       "features": {...}, "intelligence": {...}, "detections": {...}, "warnings": []}}

data: {"type": "error", "message": "Extraction timed out after 120s."}`}
                </pre>
                <p className="mt-4"><code>GET /health</code> reports the active mode and which optional analysis tools are available.</p>
              </div>
            </div>
          </section>

          {/* Supported Architectures Section */}
          <section>
            <div className="flex items-center space-x-3 mb-6">
              <Book className="w-6 h-6 text-cyan-400" />
              <h2 className="text-2xl font-bold text-white">Supported Formats</h2>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 border border-gray-800 rounded-lg bg-gray-900/30">
                <h4 className="font-bold text-white mb-2">Packages</h4>
                <ul className="list-disc pl-5 text-sm text-gray-400 space-y-1">
                  <li>PyPI wheels and sdists (.whl, .tar.gz)</li>
                  <li>npm tarballs (.tgz), with install-hook detection</li>
                  <li>Plain ZIP and TAR archives</li>
                </ul>
              </div>
              <div className="p-4 border border-gray-800 rounded-lg bg-gray-900/30">
                <h4 className="font-bold text-white mb-2">Native Binaries</h4>
                <ul className="list-disc pl-5 text-sm text-gray-400 space-y-1">
                  <li>Windows PE32/PE64 (.exe, .dll)</li>
                  <li>Linux ELF (x86_64, ARM)</li>
                </ul>
              </div>
              <div className="p-4 border border-gray-800 rounded-lg bg-gray-900/30">
                <h4 className="font-bold text-white mb-2">Scripts</h4>
                <ul className="list-disc pl-5 text-sm text-gray-400 space-y-1">
                  <li>Python, JavaScript (.py, .js)</li>
                  <li>Shell, PowerShell, Batch (.sh, .ps1, .bat)</li>
                  <li>Any other plain-text file (generic scan)</li>
                </ul>
              </div>
              <div className="p-4 border border-gray-800 rounded-lg bg-gray-900/30">
                <h4 className="font-bold text-white mb-2">Office Documents</h4>
                <ul className="list-disc pl-5 text-sm text-gray-400 space-y-1">
                  <li>Legacy OLE (.doc, .xls, .ppt)</li>
                  <li>OOXML with VBA macros (.docm, .xlsm)</li>
                </ul>
              </div>
            </div>
            <p className="mt-4 text-sm text-gray-500">
              Packages are unpacked in memory with strict limits: up to 40 files are analysed (install hooks first, 8 MB per file), nested archives are reported but not opened, and member paths are never written to disk.
            </p>
          </section>

        </div>
      </div>
    </div>
  );
}
