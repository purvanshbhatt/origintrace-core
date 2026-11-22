import { useMemo, useRef, useEffect, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import type { ForceGraphMethods, LinkObject, NodeObject } from 'react-force-graph-2d';
import type { FinalReport } from '../types/report';
import { truncateEnd } from '../lib/format';

interface ThreatGraphProps {
  report: FinalReport;
}

interface GraphNodeData {
  id: string;
  name: string;
  group: 'root' | 'supply' | 'ttp' | 'evidence';
  color: string;
  val: number;
}

interface GraphLinkData {
  color: string;
}

type GraphNode = NodeObject<GraphNodeData>;
type GraphLink = LinkObject<GraphNodeData, GraphLinkData>;

const MAX_LABEL_CHARS = 60;

export function ThreatGraph({ report }: ThreatGraphProps) {
  const fgRef = useRef<ForceGraphMethods<GraphNode, GraphLink> | undefined>(undefined);
  const [dimensions, setDimensions] = useState({ width: 800, height: 400 });
  const containerRef = useRef<HTMLDivElement>(null);

  // Resize graph to fit container dynamically
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver(entries => {
      if (entries[0]) {
        setDimensions({
          width: entries[0].contentRect.width,
          height: entries[0].contentRect.height
        });
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const graphData = useMemo(() => {
    const nodes: GraphNode[] = [];
    const links: GraphLink[] = [];

    // 1. Root Node (The analyzed binary)
    const rootId = 'root';
    nodes.push({
      id: rootId,
      name: truncateEnd(report.features.metadata.filename || 'Analyzed Artifact', MAX_LABEL_CHARS),
      group: 'root',
      color: '#00f0ff', // Neon Cyan
      val: 20
    });

    // 2. Supply Chain Node
    const attribution = report.intelligence.attribution;
    if (attribution && (attribution.suspected_package || attribution.ecosystem !== 'Unknown')) {
      const supplyId = 'supply_chain';
      const label = attribution.suspected_package
        ? `${attribution.ecosystem}: ${attribution.suspected_package}`
        : attribution.ecosystem;

      nodes.push({
        id: supplyId,
        name: label,
        group: 'supply',
        color: '#b142f5', // Purple
        val: 15
      });

      links.push({
        source: supplyId,
        target: rootId,
        color: 'rgba(177, 66, 245, 0.4)'
      });
    }

    // 3. MITRE TTPs and Evidence Nodes
    const mitre = report.intelligence.mitre_mapping || [];
    mitre.forEach((ttp, index) => {
      const ttpId = `ttp_${index}`;
      const ttpLabel = ttp.technique_id ? `${ttp.technique_id}: ${ttp.technique_name || ttp.tactic}` : ttp.tactic;

      nodes.push({
        id: ttpId,
        name: ttpLabel,
        group: 'ttp',
        color: '#ff003c', // Alert Red
        val: 12
      });

      links.push({
        source: ttpId,
        target: rootId,
        color: 'rgba(255, 0, 60, 0.3)'
      });

      if (ttp.evidence) {
        const evidenceId = `evidence_${index}`;
        nodes.push({
          id: evidenceId,
          name: truncateEnd(ttp.evidence, MAX_LABEL_CHARS),
          group: 'evidence',
          color: '#fbbf24', // Muted Yellow
          val: 8
        });

        links.push({
          source: evidenceId,
          target: ttpId,
          color: 'rgba(251, 191, 36, 0.3)'
        });
      }
    });

    return { nodes, links };
  }, [report]);

  return (
    <div ref={containerRef} className="w-full h-full bg-[#0B0E14] rounded-lg overflow-hidden relative">
      {/* HUD Overlay */}
      <div className="absolute top-4 left-4 z-10 pointer-events-none">
        <h3 className="text-xs text-gray-400 uppercase font-bold tracking-widest flex items-center">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse mr-2"></span>
          Provenance Knowledge Graph
        </h3>
      </div>

      <div className="absolute bottom-4 right-4 z-10 pointer-events-none text-[10px] text-gray-500 font-mono text-right">
        <div>Nodes: {graphData.nodes.length}</div>
        <div>Edges: {graphData.links.length}</div>
      </div>

      <ForceGraph2D
        ref={fgRef}
        width={dimensions.width}
        height={dimensions.height}
        graphData={graphData}
        backgroundColor="#0B0E14"
        nodeRelSize={6}
        nodeColor={node => node.color}
        linkColor={link => link.color}
        linkWidth={2}
        linkDirectionalParticles={2}
        linkDirectionalParticleSpeed={0.01}
        nodeCanvasObject={(node, ctx, globalScale) => {
          const x = node.x ?? 0;
          const y = node.y ?? 0;

          // Draw a glowing node
          ctx.beginPath();
          ctx.arc(x, y, node.val / 2, 0, 2 * Math.PI, false);
          ctx.fillStyle = node.color;
          ctx.fill();

          // Outer Glow
          ctx.shadowBlur = 15;
          ctx.shadowColor = node.color;

          // Label
          const fontSize = 12 / globalScale;
          ctx.font = `${fontSize}px "Fira Code", monospace`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
          ctx.fillText(node.name, x, y + (node.val / 2) + fontSize);

          // Reset shadow for other elements
          ctx.shadowBlur = 0;
        }}
        onEngineStop={() => fgRef.current?.zoomToFit(400, 50)}
      />
    </div>
  );
}
