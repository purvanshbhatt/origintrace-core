import { CommandPalette } from '../components/CommandPalette';
import { InvestigationWorkbench } from '../components/layout/InvestigationWorkbench';
import { AgentTimeline } from '../components/workbench/AgentTimeline';
import { IntelligenceRibbon } from '../components/workbench/IntelligenceRibbon';
import { MalwareDropzone } from '../components/workbench/MalwareDropzone';
import { useInvestigationStore } from '../store/useInvestigationStore';

/**
 * Full-screen investigation flow: drop an artifact, watch the agents work,
 * then explore the report in the four-pane workbench.
 */
export function WorkbenchPage() {
  const analysisState = useInvestigationStore((state) => state.analysisState);

  return (
    <div className="w-screen h-screen bg-background overflow-hidden flex flex-col font-sans text-text-primary selection:bg-neon-cyan/30">
      <CommandPalette />

      {/* Top Banner */}
      <IntelligenceRibbon />

      {/* Main Body */}
      <div className="flex-1 min-h-0 flex flex-row">
        <div className="flex-1 min-w-0 h-full">
          {analysisState === 'complete' ? <InvestigationWorkbench /> : <MalwareDropzone />}
        </div>

        {/* Right Side: Timeline Sidebar (fixed width, hidden until there is activity) */}
        {analysisState !== 'idle' && (
          <div className="h-full shrink-0">
            <AgentTimeline />
          </div>
        )}
      </div>
    </div>
  );
}
