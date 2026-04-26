import React from 'react';
import { Copy, Activity, ShieldAlert, Cpu } from 'lucide-react';
import { useInvestigationStore } from '../../store/useInvestigationStore';
import { motion } from 'framer-motion';

export function IntelligenceRibbon() {
  const { fileHash, fileSize, threatScore, liveStatus } = useInvestigationStore();
  
  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-neon-red';
    if (score >= 50) return 'text-neon-yellow';
    return 'text-neon-green';
  };

  const handleCopyHash = () => {
    // In a real app we'd copy to clipboard: navigator.clipboard.writeText(...)
    console.log("Copied to clipboard:", fileHash);
  };

  return (
    <div className="h-14 border-b border-border bg-surface flex items-center justify-between px-4 shrink-0 shadow-md z-10 w-full relative">
      {/* Backlight glow effect */}
      <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent"></div>

      {/* Brand & Left Section */}
      <div className="flex items-center space-x-6">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="text-neon-cyan w-6 h-6" />
          <span className="tracking-widest font-bold text-lg text-text-primary hidden sm:inline-block">ORIGIN<span className="text-neon-cyan font-light">TRACE</span></span>
        </div>
        
        <div className="h-6 w-px bg-border"></div>

        {/* File Metadata */}
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 bg-background border border-border px-3 py-1 rounded">
            <span className="text-xs text-text-muted uppercase font-semibold">Hash</span>
            <span className="font-mono text-sm text-text-primary tracking-tight">{fileHash}</span>
            <button onClick={handleCopyHash} className="text-text-muted hover:text-neon-cyan transition-colors" title="Copy value text">
              <Copy className="w-3 h-3" />
            </button>
          </div>
          
          <div className="flex items-center space-x-2 bg-background border border-border px-3 py-1 rounded hidden md:flex">
            <span className="text-xs text-text-muted uppercase font-semibold">Size</span>
            <span className="font-mono text-sm text-text-primary">{fileSize}</span>
          </div>
        </div>
      </div>

      {/* Right Section */}
      <div className="flex items-center space-x-6">
        {/* Live Status indicator */}
        <div className="flex items-center space-x-3 bg-surface-highlight border border-border px-4 py-1.5 rounded-full ring-1 ring-cyan-500/20 shadow-[0_0_15px_rgba(0,240,255,0.1)]">
          <motion.div 
            animate={{ scale: [1, 1.2, 1], opacity: [0.7, 1, 0.7] }}
            transition={{ repeat: Infinity, duration: 1.5 }}
            className="w-2 h-2 rounded-full bg-neon-cyan"
          />
          <span className="text-xs font-mono text-neon-cyan truncate max-w-[200px]">{liveStatus}</span>
        </div>

        {/* Threat Score Gauge */}
        <div className="flex items-center space-x-3 border-l border-border pl-6">
          <div className="flex flex-col items-end">
            <span className="text-[10px] uppercase font-bold text-text-muted tracking-widest">AI Threat Score</span>
            <span className={`text-2xl font-mono font-bold leading-none ${getScoreColor(threatScore)} drop-shadow-md`}>
              {threatScore}
            </span>
          </div>
          <Activity className={`w-8 h-8 ${getScoreColor(threatScore)} opacity-80`} />
        </div>
      </div>
    </div>
  );
}
