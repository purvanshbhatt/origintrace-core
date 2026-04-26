import React, { useState } from 'react';
import { Terminal, Copy, DownloadCloud, CheckCircle2 } from 'lucide-react';
import { cn } from '../../../lib/utils';
import { motion, AnimatePresence } from 'framer-motion';

const YARA_RULE = `rule origintrace_supply_chain_implant : Suspicious
{
    meta:
        description = "Detects dynamic resolution and injection via suspect imported library"
        author = "OriginTrace AI Agent"
        date = "2026-04-19"
        score = 85
        hash = "8f434346648f6b96e448b111...722f"

    strings:
        $s1 = "crypto-js-hijacked" ascii wide nocase
        $hex1 = { 4D 5A 90 00 03 00 00 00 ... 50 45 00 00 }
        $api1 = "VirtualAllocEx" ascii
        $api2 = "CreateRemoteThread" ascii

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5000KB and
        $s1 and
        all of ($api*) and
        math.entropy(0, filesize) >= 7.5
}`;

const SIGMA_RULE = `title: Suspicious Process Injection via Supply Chain Implant
id: a1b2c3d4-e5f6-7890-1234-567890abcdef
status: experimental
description: Detects process injection behaviors originating from a known hijacked library path.
author: OriginTrace AI Agent
date: 2026/04/19
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\\lsass.exe'
        SourceImage|endswith: '\\malware_variant_a.exe'
        CallTrace|contains: 'crypto-js-hijacked'
    condition: selection
level: high
tags:
    - attack.privilege_escalation
    - attack.t1055
`;

export function DetectionEngineeringPane() {
  const [activeTab, setActiveTab] = useState<'yara' | 'sigma'>('yara');
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    // navigator.clipboard.writeText(...)
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="h-full flex flex-col bg-surface overflow-hidden border-t border-border/50">
      <div className="pane-header !p-0 pr-2 flex items-center justify-between bg-surface-highlight border-b border-border/70">
        <div className="flex">
          <button 
            className={cn("px-4 py-2 text-xs font-semibold uppercase tracking-wider flex items-center border-r border-border transition-colors outline-none", activeTab === 'yara' ? "bg-[#0f172a] text-neon-cyan shadow-[inset_0_-2px_0_0_#00f0ff]" : "bg-transparent hover:bg-surface text-text-muted")}
            onClick={() => setActiveTab('yara')}
          >
            <Terminal className="w-4 h-4 mr-2" />
            YARA
          </button>
          <button 
            className={cn("px-4 py-2 text-xs font-semibold uppercase tracking-wider flex items-center border-r border-border transition-colors outline-none", activeTab === 'sigma' ? "bg-[#0f172a] text-neon-cyan shadow-[inset_0_-2px_0_0_#00f0ff]" : "bg-transparent hover:bg-surface text-text-muted")}
            onClick={() => setActiveTab('sigma')}
          >
            <Terminal className="w-4 h-4 mr-2" />
            Sigma
          </button>
        </div>

        <div className="flex space-x-2">
          <button onClick={handleCopy} className="flex items-center px-3 py-1 bg-background hover:bg-surface-highlight border border-border rounded text-[10px] text-text-secondary transition-colors group relative">
            <AnimatePresence mode="wait">
              {copied ? (
                <motion.div key="check" initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }}>
                  <CheckCircle2 className="w-3 h-3 text-neon-green" />
                </motion.div>
              ) : (
                <motion.div key="copy" initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }}>
                  <Copy className="w-3 h-3 group-hover:text-neon-cyan transition-colors" />
                </motion.div>
              )}
            </AnimatePresence>
            <span className="ml-1 uppercase tracking-widest">{copied ? 'Copied' : 'Copy'}</span>
          </button>
          
          <button className="flex items-center px-3 py-1 bg-background hover:bg-surface-highlight border border-border rounded text-[10px] text-text-secondary transition-colors group">
            <DownloadCloud className="w-3 h-3 group-hover:text-neon-cyan transition-colors" />
            <span className="ml-1 uppercase tracking-widest">SIEM</span>
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto bg-[#090e17] p-4 relative group custom-scrollbar">
        {/* Synthetic code block highlights. Real world would use Prism/Highlight.js */}
        <pre className="font-mono text-sm leading-relaxed text-text-primary/90">
          <code className="block whitespace-pre-wrap selection:bg-neon-cyan/30 selection:text-white">
            {activeTab === 'yara' && (
              <span dangerouslySetInnerHTML={{ __html: YARA_RULE
                .replace(/(rule|meta:|strings:|condition:|and|all of|filesize|\$s1|\$hex1|\$api1|\$api2)/g, '<span class="text-neon-purple font-bold">$1</span>')
                .replace(/(".*?")/g, '<span class="text-neon-yellow">$1</span>')
                .replace(/(0x[0-9a-fA-F]+|\d+)/g, '<span class="text-neon-cyan">$1</span>') 
              }} />
            )}
            
            {activeTab === 'sigma' && (
              <span dangerouslySetInnerHTML={{ __html: SIGMA_RULE
                .replace(/(title:|id:|status:|description:|author:|date:|logsource:|category:|product:|detection:|selection:|condition:|level:|tags:)/g, '<span class="text-neon-purple font-bold">$1</span>')
                .replace(/('.*?')/g, '<span class="text-neon-yellow">$1</span>')
              }} />
            )}
          </code>
        </pre>
      </div>
    </div>
  );
}
