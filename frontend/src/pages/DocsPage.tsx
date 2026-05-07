import React from 'react';
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
                OriginTrace utilizes a highly asynchronous Pipeline architecture consisting of two primary stages:
              </p>
              <ul className="list-disc pl-6 space-y-2 mb-4">
                <li><strong>Stage 1 (Static Extraction):</strong> Native bindings to <code className="text-cyan-300 bg-gray-900 px-1 rounded">pefile</code> and <code className="text-cyan-300 bg-gray-900 px-1 rounded">radare2</code> safely parse headers, compute Shannon entropy, and disassemble entrypoints without detonation.</li>
                <li><strong>Stage 2 (LLM Reasoning):</strong> Extracted context is pushed via Pydantic schemas into Google Gemini 3.0 Flash, which deterministically generates MITRE ATT&CK mapping and custom detection rules.</li>
              </ul>
              <p>
                The frontend consumes this pipeline via Server-Sent Events (SSE) multiplexed from a FastAPI backend.
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
                <p className="mb-4">Accepts a single file upload under the key <code>file</code>.</p>
                <p className="mb-2"><strong>Response Stream (SSE):</strong></p>
                <pre className="bg-black p-4 rounded text-gray-300 font-mono text-xs overflow-x-auto">
{`data: {"type": "status", "agent": "Extractor", "message": "Unpacking PE..."}
data: {"type": "complete", "data": {"features": {...}, "intelligence": {...}}}`}
                </pre>
              </div>
            </div>
          </section>

          {/* Supported Architectures Section */}
          <section>
            <div className="flex items-center space-x-3 mb-6">
              <Book className="w-6 h-6 text-cyan-400" />
              <h2 className="text-2xl font-bold text-white">Supported Architectures</h2>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 border border-gray-800 rounded-lg bg-gray-900/30">
                <h4 className="font-bold text-white mb-2">Native Binaries</h4>
                <ul className="list-disc pl-5 text-sm text-gray-400 space-y-1">
                  <li>Windows PE32/PE64 (.exe, .dll)</li>
                  <li>Linux ELF (x86_64, ARM)</li>
                </ul>
              </div>
              <div className="p-4 border border-gray-800 rounded-lg bg-gray-900/30">
                <h4 className="font-bold text-white mb-2">Package Ecosystems</h4>
                <ul className="list-disc pl-5 text-sm text-gray-400 space-y-1">
                  <li>Node Package Manager (.tgz, .npm)</li>
                  <li>Python Package Index (.whl, .tar.gz)</li>
                  <li>Raw Scripts (.py, .js, .ps1)</li>
                </ul>
              </div>
            </div>
          </section>

        </div>
      </div>
    </div>
  );
}
