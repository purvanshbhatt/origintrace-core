import { useCallback, useMemo } from 'react';
import type { MouseEvent } from 'react';
import ReactFlow, { Background, Controls, ConnectionMode, Handle, Position } from 'reactflow';
import type { Edge, Node, NodeProps } from 'reactflow';
import 'reactflow/dist/style.css';
import { Network, Database, Code, PackageSearch } from 'lucide-react';
import { useInvestigationStore } from '../../../store/useInvestigationStore';
import { truncateEnd } from '../../../lib/format';
import type { FinalReport } from '../../../types/report';

type NodeKind = 'root' | 'library' | 'artifact';

interface IndicatorNodeData {
  label: string;
  subLabel: string;
  kind: NodeKind;
  /** Untruncated value, used to cross-highlight other panes. */
  fullValue?: string;
}

const MAX_ARTIFACT_NODES = 6;
const NODE_SPACING_X = 210;

const KIND_STYLE: Record<NodeKind, string> = {
  root: 'bg-red-900/50 text-neon-red ring-1 ring-red-500/50',
  library: 'bg-purple-900/50 text-neon-purple ring-1 ring-purple-500/50',
  artifact: 'bg-yellow-900/50 text-neon-yellow ring-1 ring-yellow-500/50',
};

function KindIcon({ kind }: { kind: NodeKind }) {
  if (kind === 'root') return <Code size={12} />;
  if (kind === 'library') return <PackageSearch size={12} />;
  return <Database size={12} />;
}

function IndicatorNode({ data, selected }: NodeProps<IndicatorNodeData>) {
  return (
    <div
      className={`px-4 py-2 shadow-md rounded-md bg-[#0f172a] border-2 transition-all
      ${selected ? 'border-neon-cyan shadow-[0_0_15px_rgba(0,240,255,0.4)]' : 'border-[#334155]'} w-48`}
      title={data.fullValue ?? data.label}
    >
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-neon-cyan" />
      <div className="flex items-center space-x-2">
        <div className={`p-1.5 rounded-full ${KIND_STYLE[data.kind]}`}><KindIcon kind={data.kind} /></div>
        <div className="flex flex-col min-w-0">
          <span className="font-bold text-xs tracking-wider text-slate-100 font-mono truncate">{data.label}</span>
          <span className="text-[9px] text-slate-400 uppercase">{data.subLabel}</span>
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-neon-cyan" />
    </div>
  );
}

const nodeTypes = { indicator: IndicatorNode };

/** Build sample → matched library → injected artifacts from the report. */
function buildGraph(report: FinalReport): { nodes: Node<IndicatorNodeData>[]; edges: Edge[] } {
  const { metadata, provenance, file_type: fileType } = report.features;
  const { attribution } = report.intelligence;
  const nodes: Node<IndicatorNodeData>[] = [];
  const edges: Edge[] = [];

  const artifacts = (provenance.injected_artifacts ?? []).slice(0, MAX_ARTIFACT_NODES);
  const rowWidth = Math.max(artifacts.length - 1, 0) * NODE_SPACING_X;
  const centerX = rowWidth / 2;

  nodes.push({
    id: 'root', type: 'indicator', position: { x: centerX, y: 0 },
    data: { label: truncateEnd(metadata.filename, 22), subLabel: `Sample (${fileType})`, kind: 'root', fullValue: metadata.filename },
  });

  const library = attribution.suspected_package;
  if (library) {
    nodes.push({
      id: 'library', type: 'indicator', position: { x: centerX, y: 120 },
      data: { label: truncateEnd(library, 22), subLabel: `${attribution.ecosystem} · matched library`, kind: 'library', fullValue: provenance.ecosystem_match },
    });
    edges.push({ id: 'e-root-library', source: 'root', target: 'library', animated: true, style: { stroke: '#00f0ff', strokeWidth: 2 }, label: 'Resembles' });
  }

  artifacts.forEach((artifact, i) => {
    const id = `artifact-${i}`;
    nodes.push({
      id, type: 'indicator', position: { x: i * NODE_SPACING_X, y: library ? 250 : 130 },
      data: { label: truncateEnd(artifact, 22), subLabel: library ? 'Injected artifact' : 'Extracted artifact', kind: 'artifact', fullValue: artifact },
    });
    edges.push({
      id: `e-${id}`, source: library ? 'library' : 'root', target: id, animated: true,
      style: { stroke: '#ff003c', strokeWidth: 2, strokeDasharray: '5 5' }, label: library ? 'Delta' : undefined,
    });
  });

  return { nodes, edges };
}

export function AttributionGraphPane() {
  const report = useInvestigationStore((state) => state.finalReport);
  const setSelectedIndicator = useInvestigationStore((state) => state.setSelectedIndicator);

  const graph = useMemo(() => (report ? buildGraph(report) : null), [report]);

  const onNodeClick = useCallback((_: MouseEvent, node: Node<IndicatorNodeData>) => {
    setSelectedIndicator(node.data.kind === 'artifact' ? node.data.fullValue ?? null : null);
  }, [setSelectedIndicator]);
  const onPaneClick = useCallback(() => { setSelectedIndicator(null); }, [setSelectedIndicator]);

  const hidden = report ? (report.features.provenance.injected_artifacts?.length ?? 0) - MAX_ARTIFACT_NODES : 0;

  return (
    <div className="h-full flex flex-col bg-surface border-border overflow-hidden">
      <div className="pane-header flex justify-between items-center z-10 w-full relative">
        <div className="flex items-center space-x-2">
          <Network className="w-4 h-4 text-neon-cyan" />
          <span>Supply Chain Attribution Graph</span>
        </div>
        {hidden > 0 && <span className="normal-case text-text-muted">+{hidden} more artifact(s) in the report</span>}
      </div>
      <div className="flex-1 relative bg-[#020617]">
        <div className="absolute inset-0 pointer-events-none bg-cyber-grid opacity-30 z-0 mix-blend-screen" />
        {graph && (
          <ReactFlow
            // Uncontrolled: remount when the analysed sample changes.
            key={report?.features.metadata.sha256 ?? report?.features.metadata.filename}
            defaultNodes={graph.nodes}
            defaultEdges={graph.edges}
            onNodeClick={onNodeClick}
            onPaneClick={onPaneClick}
            nodeTypes={nodeTypes}
            connectionMode={ConnectionMode.Loose}
            nodesConnectable={false}
            fitView
            fitViewOptions={{ padding: 0.2, maxZoom: 1 }}
            className="z-10"
          >
            <Background color="#1e293b" gap={16} size={1} />
            <Controls showInteractive={false} className="bg-[#0f172a] border-[#334155] fill-slate-300" style={{ display: 'flex', flexDirection: 'column' }} />
          </ReactFlow>
        )}
      </div>
    </div>
  );
}
