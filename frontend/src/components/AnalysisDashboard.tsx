import React, { useState, useRef, useEffect } from 'react';
import { UploadCloud, FileCode, ShieldAlert, Cpu, CheckCircle2, Copy, AlertCircle, ShieldBan, Terminal } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

// --- Type Definitions for the Dashboard State ---
type AnalysisState = 'idle' | 'analyzing' | 'complete' | 'error';

interface FinalReport {
  features: any;
  intelligence: {
    threat_level: string;
    behavioral_summary: string;
    mitre_mapping: Array<{ tactic: string; technique_id: string; evidence: string }>;
    attribution: {
      ecosystem: string;
      suspected_package?: string;
    };
  };
  detections: {
    yara_rule: string;
    sigma_rule: string;
  };
}

export function AnalysisDashboard() {
  const [status, setStatus] = useState<AnalysisState>('idle');
  const [messages, setMessages] = useState<{ id: number; text: string }[]>([]);
  const [report, setReport] = useState<FinalReport | null>(null);
  const [errorMsg, setErrorMsg] = useState<string>('');
  
  // Drag state
  const [isDragging, setIsDragging] = useState(false);
  
  // Code Viewer Tab
  const [activeTab, setActiveTab] = useState<'yara' | 'sigma'>('yara');
  const [copied, setCopied] = useState(false);

  // Auto-scroll terminal
  const terminalEndRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (status === 'analyzing') {
      terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, status]);

  // --- 1. Fetch Logic & SSE Parsing ---
  const handleFileUpload = async (file: File) => {
    setStatus('analyzing');
    setMessages([{ id: Date.now(), text: `[SYSTEM] Uploading ${file.name} for Autonomous Semantic Provenance...` }]);
    setReport(null);
    setErrorMsg('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://localhost:8080/api/v1/analyze', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) throw new Error(`Server returned status: ${response.status}`);
      if (!response.body) throw new Error('ReadableStream not supported.');

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');

      let stepCounter = 0;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.trim() === '') continue;

          if (line.startsWith('data: ')) {
            try {
              const payload = JSON.parse(line.substring(6));
              
              if (payload.type === 'status') {
                setMessages(prev => [...prev, { 
                  id: Date.now() + stepCounter++, 
                  text: `[${payload.agent}] ${payload.message}` 
                }]);
              } else if (payload.type === 'complete') {
                setReport(payload.data);
                setStatus('complete');
              } else if (payload.type === 'error') {
                throw new Error(payload.message);
              }
            } catch (err) {
              console.error("SSE Parse Error:", err);
            }
          }
        }
      }
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.message || 'Stream connection failed.');
      setStatus('error');
    }
  };

  // --- Drag and Drop Handlers ---
  const onDragOver = (e: React.DragEvent) => { e.preventDefault(); setIsDragging(true); };
  const onDragLeave = (e: React.DragEvent) => { e.preventDefault(); setIsDragging(false); };
  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };
  const onFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileUpload(e.target.files[0]);
    }
  };

  // --- Helpers ---
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getThreatColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'high': return 'bg-red-950 border-red-500 text-red-500';
      case 'medium': return 'bg-yellow-950 border-yellow-500 text-yellow-500';
      case 'low': return 'bg-green-950 border-green-500 text-green-500';
      default: return 'bg-gray-800 border-gray-600 text-gray-400';
    }
  };

  // --- Render Functions ---
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans p-8 overflow-x-hidden">
      
      {/* Header */}
      <header className="max-w-6xl mx-auto mb-12 border-b border-gray-800 pb-4 flex items-center space-x-3">
        <ShieldAlert className="w-8 h-8 text-cyan-400" />
        <div>
          <h1 className="text-2xl font-bold tracking-widest text-white">ORIGIN<span className="text-cyan-400 font-light">TRACE</span></h1>
          <p className="text-xs text-gray-500 font-mono tracking-widest uppercase">Autonomous Semantic Provenance</p>
        </div>
      </header>

      <main className="max-w-6xl mx-auto">
        <AnimatePresence mode="wait">
          
          {/* STATE: IDLE (Dropzone) */}
          {status === 'idle' && (
            <motion.div 
              key="dropzone"
              initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95 }}
              className={`relative flex flex-col items-center justify-center p-16 border-2 border-dashed rounded-xl transition-all duration-300 ${
                isDragging ? 'border-cyan-400 bg-cyan-950/20' : 'border-gray-800 hover:border-gray-600 bg-gray-900/50'
              }`}
              onDragOver={onDragOver}
              onDragLeave={onDragLeave}
              onDrop={onDrop}
            >
              <input type="file" className="absolute inset-0 w-full h-full opacity-0 cursor-pointer" onChange={onFileInput} />
              <div className="p-4 bg-gray-950 rounded-full border border-gray-800 mb-6 relative">
                <UploadCloud className="w-12 h-12 text-cyan-400" />
              </div>
              <h2 className="text-2xl font-mono font-semibold mb-2">Initialize Threat Analysis</h2>
              <p className="text-gray-500 text-sm">Drag and drop a suspect binary or package here, or click to browse.</p>
            </motion.div>
          )}

          {/* STATE: ANALYZING (Terminal) */}
          {status === 'analyzing' && (
            <motion.div 
              key="terminal"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0, y: -20 }}
              className="bg-black border border-gray-800 rounded-lg overflow-hidden shadow-[0_0_30px_rgba(0,229,255,0.05)]"
            >
              <div className="bg-gray-900 px-4 py-2 border-b border-gray-800 flex items-center">
                <Terminal className="w-4 h-4 text-cyan-400 mr-2" />
                <span className="text-xs font-mono text-gray-400 uppercase">Engine Live Stream</span>
              </div>
              <div className="p-6 h-96 overflow-y-auto font-mono text-sm leading-relaxed custom-scrollbar">
                {messages.map((msg, i) => (
                  <motion.div 
                    key={msg.id} 
                    initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                    className="mb-2 text-gray-300"
                  >
                    <span className="text-cyan-500 mr-2">{'>'}</span>{msg.text}
                  </motion.div>
                ))}
                <div className="flex items-center mt-4">
                  <span className="text-cyan-500 mr-2">{'>'}</span>
                  <span className="w-2 h-4 bg-cyan-400 animate-pulse"></span>
                </div>
                <div ref={terminalEndRef} />
              </div>
            </motion.div>
          )}

          {/* STATE: COMPLETE (Dashboard) */}
          {status === 'complete' && report && (
            <motion.div 
              key="dashboard"
              initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }}
              className="grid grid-cols-1 lg:grid-cols-3 gap-6"
            >
              {/* Left Column */}
              <div className="lg:col-span-1 space-y-6">
                
                {/* Threat Badge */}
                <div className={`p-6 rounded-lg border ${getThreatColor(report.intelligence.threat_level)} flex items-center justify-between shadow-lg`}>
                  <div>
                    <div className="text-[10px] uppercase tracking-widest font-bold opacity-70 mb-1">Severity</div>
                    <div className="text-2xl font-bold uppercase tracking-wider">{report.intelligence.threat_level}</div>
                  </div>
                  <ShieldBan className="w-10 h-10 opacity-80" />
                </div>

                {/* Attribution Card */}
                <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
                  <h3 className="text-xs text-gray-400 uppercase font-bold tracking-widest mb-4 flex items-center border-b border-gray-800 pb-2">
                    <Cpu className="w-4 h-4 mr-2 text-cyan-400" />
                    Supply Chain Origin
                  </h3>
                  <div className="space-y-4">
                    <div>
                      <div className="text-[10px] text-gray-500 uppercase">Ecosystem</div>
                      <div className="font-mono text-gray-200">{report.intelligence.attribution?.ecosystem || 'Native'}</div>
                    </div>
                    {report.intelligence.attribution?.suspected_package && (
                      <div>
                        <div className="text-[10px] text-gray-500 uppercase">Suspected Package</div>
                        <div className="font-mono text-cyan-400 bg-cyan-950/30 px-2 py-1 rounded inline-block mt-1 border border-cyan-900/50">
                          {report.intelligence.attribution.suspected_package}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Behavioral Narrative */}
                <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
                  <h3 className="text-xs text-gray-400 uppercase font-bold tracking-widest mb-4 border-b border-gray-800 pb-2">
                    Behavioral Narrative
                  </h3>
                  <p className="text-sm text-gray-300 leading-relaxed font-sans">
                    {report.intelligence.behavioral_summary}
                  </p>
                </div>
              </div>

              {/* Right Column */}
              <div className="lg:col-span-2 space-y-6">
                
                {/* MITRE ATT&CK */}
                <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden flex flex-col">
                  <div className="px-6 py-4 border-b border-gray-800 bg-gray-900/80">
                    <h3 className="text-xs text-gray-400 uppercase font-bold tracking-widest">MITRE ATT&CK Mapping</h3>
                  </div>
                  <div className="p-4 overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead className="text-xs text-gray-500 font-mono border-b border-gray-800">
                        <tr>
                          <th className="pb-3 pr-4 font-normal">Technique</th>
                          <th className="pb-3 pr-4 font-normal">Tactic</th>
                          <th className="pb-3 font-normal">AI Evidence</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800/50">
                        {report.intelligence.mitre_mapping?.map((ttp, idx) => (
                          <tr key={idx} className="group hover:bg-gray-800/20 transition-colors">
                            <td className="py-3 pr-4 font-mono text-cyan-400 align-top whitespace-nowrap">{ttp.technique_id || ttp.tactic}</td>
                            <td className="py-3 pr-4 text-gray-300 align-top">{ttp.tactic}</td>
                            <td className="py-3 text-gray-400 text-xs leading-relaxed">{ttp.evidence}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Detection Engineering (Split Pane) */}
                <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden flex flex-col h-[400px]">
                  <div className="flex border-b border-gray-800 bg-black/50">
                    <button 
                      onClick={() => setActiveTab('yara')}
                      className={`px-6 py-3 text-xs font-bold tracking-widest uppercase transition-colors ${activeTab === 'yara' ? 'text-cyan-400 border-b-2 border-cyan-400' : 'text-gray-500 hover:text-gray-300'}`}
                    >
                      YARA Rule
                    </button>
                    <button 
                      onClick={() => setActiveTab('sigma')}
                      className={`px-6 py-3 text-xs font-bold tracking-widest uppercase transition-colors ${activeTab === 'sigma' ? 'text-cyan-400 border-b-2 border-cyan-400' : 'text-gray-500 hover:text-gray-300'}`}
                    >
                      Sigma Rule
                    </button>
                    <div className="ml-auto flex items-center pr-4">
                      <button 
                        onClick={() => handleCopy(activeTab === 'yara' ? report.detections.yara_rule : report.detections.sigma_rule)}
                        className="text-gray-500 hover:text-white transition-colors flex items-center text-xs uppercase tracking-wider font-bold bg-gray-800 px-3 py-1.5 rounded"
                      >
                        {copied ? <CheckCircle2 className="w-4 h-4 mr-2 text-green-400" /> : <Copy className="w-4 h-4 mr-2" />}
                        {copied ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>
                  
                  <div className="flex-1 bg-black p-6 overflow-auto custom-scrollbar">
                    <pre className="font-mono text-[13px] leading-relaxed text-gray-300 whitespace-pre-wrap">
                      <code>
                        {activeTab === 'yara' ? report.detections.yara_rule : report.detections.sigma_rule}
                      </code>
                    </pre>
                  </div>
                </div>

              </div>
            </motion.div>
          )}

          {/* STATE: ERROR */}
          {status === 'error' && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-8">
              <div className="bg-red-950/50 border border-red-500/50 text-red-400 p-6 rounded-lg flex items-start shadow-2xl">
                <AlertCircle className="w-6 h-6 mr-4 shrink-0" />
                <div>
                  <h3 className="text-lg font-bold mb-1">Analysis Failed</h3>
                  <p className="font-mono text-sm opacity-80">{errorMsg}</p>
                  <button 
                    onClick={() => setStatus('idle')}
                    className="mt-4 px-4 py-2 bg-red-900/50 hover:bg-red-900 text-white rounded text-sm transition-colors border border-red-800"
                  >
                    Reset Dashboard
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <style dangerouslySetInnerHTML={{__html: `
        .custom-scrollbar::-webkit-scrollbar { width: 8px; height: 8px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: #030712; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #1f2937; border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #374151; }
      `}} />
    </div>
  );
}
