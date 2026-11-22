import { useMemo } from 'react';
import { Target } from 'lucide-react';
import { useInvestigationStore } from '../../../store/useInvestigationStore';
import { cn } from '../../../lib/utils';
import type { MitreTechnique } from '../../../types/report';

export function MitreAttackPane() {
  const report = useInvestigationStore((state) => state.finalReport);
  const selectedIndicator = useInvestigationStore((state) => state.selectedIndicator);

  const techniques = useMemo<MitreTechnique[]>(() => report?.intelligence.mitre_mapping ?? [], [report]);

  // Group by Tactic, preserving the order the backend reports them in
  const grouped = useMemo(() => {
    return techniques.reduce((acc, curr) => {
      const tactic = curr.tactic || 'Unknown';
      if (!acc[tactic]) acc[tactic] = [];
      acc[tactic].push(curr);
      return acc;
    }, {} as Record<string, MitreTechnique[]>);
  }, [techniques]);

  // Cross-highlight: techniques whose evidence cites the artifact selected in the graph.
  const isCited = (technique: MitreTechnique) =>
    selectedIndicator !== null && technique.evidence.includes(selectedIndicator);
  const anyCited = techniques.some(isCited);

  return (
    <div className="h-full flex flex-col bg-surface overflow-hidden">
      <div className="pane-header flex items-center !justify-start">
        <Target className="w-4 h-4 mr-2" />
        MITRE ATT&CK Matrix
        {anyCited && <span className="ml-2 text-neon-purple normal-case">— citing the selected artifact</span>}
      </div>

      <div className="flex-1 overflow-x-auto overflow-y-auto custom-scrollbar p-4">
        {techniques.length === 0 ? (
          <div className="h-full flex items-center justify-center text-sm text-text-muted text-center px-6">
            No ATT&CK techniques were mapped for this sample.
          </div>
        ) : (
          <div className="flex space-x-2 min-w-max">
            {Object.entries(grouped).map(([tactic, tacticTechniques]) => (
              <div key={tactic} className="w-56 shrink-0 flex flex-col">
                <div className="text-[10px] font-bold uppercase tracking-wider text-text-secondary bg-surface-highlight py-1.5 px-2 mb-2 rounded border border-border/50 truncate" title={tactic}>
                  {tactic}
                </div>
                <div className="flex flex-col space-y-2">
                  {tacticTechniques.map((tech) => (
                    <div
                      key={`${tech.technique_id}-${tech.evidence}`}
                      className={cn(
                        "p-2 border rounded text-xs transition-all duration-200 border-neon-red/40 bg-red-900/10",
                        anyCited && !isCited(tech) && "opacity-30",
                        isCited(tech) && "border-neon-purple shadow-[0_0_10px_rgba(177,66,245,0.3)]"
                      )}
                    >
                      <div className="font-mono text-[10px] mb-1 text-neon-red/90">{tech.technique_id}</div>
                      <div className="font-semibold leading-tight text-text-primary">{tech.technique_name || tech.technique_id}</div>
                      <div className="mt-2 text-[11px] text-text-secondary font-mono leading-relaxed break-words whitespace-pre-wrap">
                        {tech.evidence}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="h-6 shrink-0 bg-surface-highlight flex flex-row items-center px-4 border-t border-border">
        <span className="text-[10px] text-text-muted uppercase font-bold tracking-widest">
          {techniques.length} technique(s) · {Object.keys(grouped).length} tactic(s)
          {report ? ` · engine: ${report.intelligence.engine}` : ''}
        </span>
      </div>
    </div>
  );
}
