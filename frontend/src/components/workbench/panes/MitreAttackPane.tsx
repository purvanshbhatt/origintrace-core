import React, { useMemo } from 'react';
import { Target } from 'lucide-react';
import { useInvestigationStore } from '../../../store/useInvestigationStore';
import { cn } from '../../../lib/utils';

interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  evidence: string;
  confidence: 'High' | 'Medium' | 'Low';
}

const mtcData: AttackTechnique[] = [
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', evidence: 'Cmd.exe spawned with suspicious encoded Base64 parameters.', confidence: 'High' },
  { id: 'T1055', name: 'Process Injection', tactic: 'Privilege Escalation', evidence: 'CreateRemoteThread discovered targeting lsass.exe', confidence: 'High' },
  { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery', evidence: 'Registry queries to HKLM\\Software\\Microsoft\\Cryptography', confidence: 'Medium' },
  { id: 'T1140', name: 'Deobfuscate/Decode Files or Information', tactic: 'Defense Evasion', evidence: 'Custom XOR decoding loop found in suspect import crypto-js-hijacked.', confidence: 'High' },
  { id: 'T1571', name: 'Non-Standard Port', tactic: 'Command and Control', evidence: 'Outbound TCP connection attempted on port 13337.', confidence: 'Low' },
  { id: 'T1566', name: 'Phishing', tactic: 'Initial Access', evidence: '-', confidence: 'Low' },
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', evidence: '-', confidence: 'Low' },
];

export function MitreAttackPane() {
  const { selectedGraphNodeId } = useInvestigationStore();

  const getConfidenceColor = (conf: string) => {
    switch(conf) {
      case 'High': return 'border-neon-red/50 bg-red-900/10 text-neon-red shadow-[inset_0_0_10px_rgba(255,0,60,0.1)] glow-text-red';
      case 'Medium': return 'border-neon-yellow/50 bg-yellow-900/10 text-neon-yellow';
      default: return 'border-border/30 bg-surface/50 text-text-muted opacity-50';
    }
  };

  // Group by Tactic
  const grouped = useMemo(() => {
    return mtcData.reduce((acc, curr) => {
      if (!acc[curr.tactic]) acc[curr.tactic] = [];
      acc[curr.tactic].push(curr);
      return acc;
    }, {} as Record<string, AttackTechnique[]>);
  }, []);

  const highlightedTactic = selectedGraphNodeId === '3' ? 'Defense Evasion' : null;

  return (
    <div className="h-full flex flex-col bg-surface overflow-hidden">
      <div className="pane-header flex items-center">
        <Target className="w-4 h-4 mr-2" />
        MITRE ATT&CK Matrix {selectedGraphNodeId === '3' && <span className="ml-2 text-neon-purple lowercase animate-pulse">- filtering by selected node</span>}
      </div>

      <div className="flex-1 overflow-x-auto overflow-y-auto custom-scrollbar p-4">
        <div className="flex space-x-2 min-w-max">
          {Object.entries(grouped).map(([tactic, techniques]) => {
            const isHighlightedTactic = highlightedTactic === tactic;

            return (
              <div key={tactic} className={cn(
                "w-48 shrink-0 flex flex-col transition-opacity", 
                highlightedTactic && !isHighlightedTactic ? "opacity-30" : "opacity-100"
              )}>
                <div className="text-[10px] font-bold uppercase tracking-wider text-text-secondary bg-surface-highlight py-1.5 px-2 mb-2 rounded border border-border/50 truncate" title={tactic}>
                  {tactic}
                </div>
                <div className="flex flex-col space-y-2">
                  {techniques.map(tech => (
                    <div 
                      key={tech.id}
                      className={cn(
                        "group relative p-2 border rounded text-xs cursor-crosshair transition-all duration-200",
                        getConfidenceColor(tech.confidence),
                        tech.confidence !== 'Low' && "hover:bg-surface-highlight hover:-translate-y-0.5"
                      )}
                    >
                      <div className="font-mono text-[10px] mb-1 opacity-80">{tech.id}</div>
                      <div className="font-semibold leading-tight">{tech.name}</div>
                      
                      {/* Hover Popover containing AI Evidence */}
                      {tech.confidence !== 'Low' && (
                        <div className="absolute top-1/2 left-full -translate-y-1/2 ml-2 w-64 bg-background border border-neon-cyan/50 rounded shadow-2xl z-50 p-3 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all pointer-events-none">
                          <div className="text-[9px] uppercase font-bold text-neon-cyan mb-1 tracking-widest">AI Evidence</div>
                          <div className="text-xs text-text-primary font-mono whitespace-pre-wrap leading-relaxed">{tech.evidence}</div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>
      
      {/* Legend */}
      <div className="h-6 shrink-0 bg-surface-highlight flex flex-row items-center px-4 space-x-4 border-t border-border">
         <span className="text-[9px] text-text-muted uppercase font-bold tracking-widest">Confidence:</span>
         <div className="flex items-center space-x-1"><div className="w-2 h-2 rounded-full bg-neon-red shadow-[0_0_5px_#ff003c]"></div><span className="text-[10px] text-text-secondary">High</span></div>
         <div className="flex items-center space-x-1"><div className="w-2 h-2 rounded-full bg-neon-yellow"></div><span className="text-[10px] text-text-secondary">Medium</span></div>
         <div className="flex items-center space-x-1"><div className="w-2 h-2 rounded-full bg-slate-600"></div><span className="text-[10px] text-text-secondary">Low</span></div>
      </div>
    </div>
  );
}
