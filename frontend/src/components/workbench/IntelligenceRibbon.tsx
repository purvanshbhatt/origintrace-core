import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, AlertTriangle, Check, Copy, RotateCcw, ShieldAlert } from 'lucide-react';
import { motion } from 'framer-motion';
import { useInvestigationStore } from '../../store/useInvestigationStore';
import { copyText } from '../../lib/browser';
import { formatBytes, truncateMiddle } from '../../lib/format';
import type { FinalReport } from '../../types/report';

const scoreColor = (score: number): string => {
  if (score >= 65) return 'text-neon-red';
  if (score >= 30) return 'text-neon-yellow';
  return 'text-neon-green';
};

/** Label describing which engine produced the findings. */
function engineLabel(report: FinalReport): string {
  if (report.mode === 'mock') return 'Demo data';
  const engine = report.intelligence.engine;
  if (report.mode === 'llm' && engine !== 'gemini') return 'Heuristic (LLM fallback)';
  return engine === 'gemini' ? 'Gemini' : 'Heuristic';
}

export function IntelligenceRibbon() {
  const report = useInvestigationStore((state) => state.finalReport);
  const fileName = useInvestigationStore((state) => state.fileName);
  const fileSize = useInvestigationStore((state) => state.fileSize);
  const liveStatus = useInvestigationStore((state) => state.liveStatus);
  const analysisState = useInvestigationStore((state) => state.analysisState);
  const reset = useInvestigationStore((state) => state.reset);
  const [copied, setCopied] = useState(false);

  const sha256 = report?.features.metadata.sha256 ?? null;
  const score = report?.intelligence.threat_score ?? null;
  const warnings = report?.warnings ?? [];
  const isActive = analysisState === 'analyzing';

  const handleCopyHash = async () => {
    if (!sha256 || !(await copyText(sha256))) return;
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="h-14 border-b border-border bg-surface flex items-center justify-between px-4 shrink-0 shadow-md z-10 w-full relative">
      {/* Backlight glow effect */}
      <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent"></div>

      {/* Brand & Left Section */}
      <div className="flex items-center space-x-6 min-w-0">
        <Link to="/" className="flex items-center space-x-2 shrink-0" title="Back to home">
          <ShieldAlert className="text-neon-cyan w-6 h-6" />
          <span className="tracking-widest font-bold text-lg text-text-primary hidden sm:inline-block">ORIGIN<span className="text-neon-cyan font-light">TRACE</span></span>
        </Link>

        <div className="h-6 w-px bg-border shrink-0"></div>

        {/* File Metadata */}
        <div className="flex items-center space-x-4 min-w-0">
          {fileName && (
            <div className="hidden lg:flex items-center space-x-2 bg-background border border-border px-3 py-1 rounded min-w-0">
              <span className="text-xs text-text-muted uppercase font-semibold">File</span>
              <span className="font-mono text-sm text-text-primary truncate max-w-[180px]" title={fileName}>{fileName}</span>
            </div>
          )}

          <div className="flex items-center space-x-2 bg-background border border-border px-3 py-1 rounded whitespace-nowrap">
            <span className="text-xs text-text-muted uppercase font-semibold">SHA256</span>
            <span className="font-mono text-sm text-text-primary tracking-tight" title={sha256 ?? undefined}>
              {sha256 ? truncateMiddle(sha256) : '—'}
            </span>
            <button
              onClick={handleCopyHash}
              disabled={!sha256}
              className="text-text-muted hover:text-neon-cyan transition-colors disabled:opacity-30 disabled:hover:text-text-muted"
              title="Copy SHA256"
              aria-label="Copy SHA256"
            >
              {copied ? <Check className="w-3 h-3 text-neon-green" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>

          <div className="items-center space-x-2 bg-background border border-border px-3 py-1 rounded hidden md:flex whitespace-nowrap">
            <span className="text-xs text-text-muted uppercase font-semibold">Size</span>
            <span className="font-mono text-sm text-text-primary">{formatBytes(fileSize)}</span>
          </div>
        </div>
      </div>

      {/* Right Section */}
      <div className="flex items-center space-x-4 shrink-0">
        {warnings.length > 0 && (
          <div
            className="hidden md:flex items-center space-x-1 text-neon-yellow text-xs font-mono border border-neon-yellow/40 rounded px-2 py-1"
            title={warnings.join('\n')}
          >
            <AlertTriangle className="w-3 h-3" />
            <span>{warnings.length} notice{warnings.length > 1 ? 's' : ''}</span>
          </div>
        )}

        {report && (
          <span className="hidden md:inline-block text-[10px] uppercase font-bold tracking-widest text-text-secondary border border-border rounded px-2 py-1">
            {engineLabel(report)}
          </span>
        )}

        {/* Live Status indicator */}
        <div className="flex items-center space-x-3 bg-surface-highlight border border-border px-4 py-1.5 rounded-full ring-1 ring-cyan-500/20 shadow-[0_0_15px_rgba(0,240,255,0.1)]">
          <motion.div
            animate={isActive ? { scale: [1, 1.2, 1], opacity: [0.7, 1, 0.7] } : { scale: 1, opacity: 0.6 }}
            transition={isActive ? { repeat: Infinity, duration: 1.5 } : { duration: 0.2 }}
            className={`w-2 h-2 rounded-full ${analysisState === 'error' ? 'bg-neon-red' : 'bg-neon-cyan'}`}
          />
          <span className="text-xs font-mono text-neon-cyan truncate max-w-[220px]" title={liveStatus}>{liveStatus}</span>
        </div>

        {analysisState !== 'idle' && !isActive && (
          <button
            onClick={reset}
            className="flex items-center space-x-1 text-xs font-semibold uppercase tracking-wider text-text-secondary hover:text-neon-cyan border border-border hover:border-neon-cyan/50 rounded px-3 py-1.5 transition-colors"
          >
            <RotateCcw className="w-3 h-3" />
            <span>New analysis</span>
          </button>
        )}

        {/* Threat Score Gauge */}
        <div className="flex items-center space-x-3 border-l border-border pl-4">
          <div className="flex flex-col items-end">
            <span className="text-[10px] uppercase font-bold text-text-muted tracking-widest">Threat Score</span>
            <span className={`text-2xl font-mono font-bold leading-none drop-shadow-md ${score === null ? 'text-text-muted' : scoreColor(score)}`}>
              {score ?? '—'}
            </span>
          </div>
          <Activity className={`w-8 h-8 opacity-80 ${score === null ? 'text-text-muted' : scoreColor(score)}`} />
        </div>
      </div>
    </div>
  );
}
