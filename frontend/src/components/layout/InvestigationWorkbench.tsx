import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';
import { MalwareSummaryPane } from '../workbench/panes/MalwareSummaryPane';
import { AttributionGraphPane } from '../workbench/panes/AttributionGraphPane';
import { MitreAttackPane } from '../workbench/panes/MitreAttackPane';
import { DetectionEngineeringPane } from '../workbench/panes/DetectionEngineeringPane';
import { GripVertical, GripHorizontal } from 'lucide-react';

// Custom Resize Handle component for that premium IDE feel
const CustomResizeHandle = ({ direction = 'horizontal' }: { direction?: 'horizontal' | 'vertical' }) => (
  <PanelResizeHandle className={`relative flex items-center justify-center bg-border hover:bg-neon-cyan/50 transition-colors z-20
    ${direction === 'horizontal' ? 'w-1 cursor-col-resize' : 'h-1 cursor-row-resize'}`}>
    <div className={`absolute flex items-center justify-center bg-surface border border-border rounded shadow max-w-fit max-h-fit
      ${direction === 'horizontal' ? 'w-3 h-8' : 'h-3 w-8'}`}>
      {direction === 'horizontal' ? (
        <GripVertical className="w-2.5 h-2.5 text-text-muted" />
      ) : (
        <GripHorizontal className="w-2.5 h-2.5 text-text-muted" />
      )}
    </div>
  </PanelResizeHandle>
);

/** The four resizable report panes shown once an analysis has completed. */
export function InvestigationWorkbench() {
  return (
    <div className="w-full h-full overflow-hidden">
      <PanelGroup direction="horizontal">

        {/* Left Column (Panes A & C) */}
        <Panel defaultSize={35} minSize={20}>
          <PanelGroup direction="vertical">
            {/* PANE A: Malware Summary */}
            <Panel defaultSize={45} minSize={20}>
              <MalwareSummaryPane />
            </Panel>

            <CustomResizeHandle direction="vertical" />

            {/* PANE C: MITRE ATT&CK */}
            <Panel defaultSize={55} minSize={20}>
              <MitreAttackPane />
            </Panel>
          </PanelGroup>
        </Panel>

        <CustomResizeHandle direction="horizontal" />

        {/* Right Column (Panes B & D) */}
        <Panel defaultSize={65} minSize={30}>
          <PanelGroup direction="vertical">
            {/* PANE B: Attribution Graph */}
            <Panel defaultSize={55} minSize={20}>
              <AttributionGraphPane />
            </Panel>

            <CustomResizeHandle direction="vertical" />

            {/* PANE D: Detection Engineering */}
            <Panel defaultSize={45} minSize={20}>
              <DetectionEngineeringPane />
            </Panel>
          </PanelGroup>
        </Panel>

      </PanelGroup>
    </div>
  );
}

export default InvestigationWorkbench;
