import React, { useCallback, useMemo } from 'react';
import ReactFlow, { 
  Background, 
  Controls, 
  MarkerType, 
  Node, 
  Edge,
  useNodesState,
  useEdgesState,
  ConnectionMode,
  Handle,
  Position
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Network, Database, Code, PackageSearch, Github } from 'lucide-react';
import { useInvestigationStore } from '../../../store/useInvestigationStore';

// Custom Node to match Cyber-Dark Theme
const CustomSvelteNode = ({ data, selected }: any) => {
  return (
    <div className={`px-4 py-2 shadow-md rounded-md bg-[#0f172a] border-2 transition-all 
      ${selected ? 'border-neon-cyan shadow-[0_0_15px_rgba(0,240,255,0.4)]' : 'border-[#334155]'}
      w-48`}>
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-neon-cyan" />
      <div className="flex items-center space-x-2">
        <div className={`p-1.5 rounded-full ${data.iconColor || 'bg-slate-700 text-slate-300'}`}>
          {data.icon}
        </div>
        <div className="flex flex-col">
          <span className="font-bold text-xs tracking-wider text-slate-100 font-mono truncate">{data.label}</span>
          <span className="text-[9px] text-slate-400 uppercase">{data.subLabel}</span>
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-neon-cyan" />
    </div>
  );
};

const initialNodes: Node[] = [
  { 
    id: '1', 
    type: 'custom', 
    position: { x: 250, y: 50 }, 
    data: { label: 'malware_variant_a.exe', subLabel: 'Binary (Root)', icon: <Code size={12}/>, iconColor: 'bg-red-900/50 text-neon-red ring-1 ring-red-500/50' } 
  },
  { 
    id: '2', 
    type: 'custom', 
    position: { x: 250, y: 150 }, 
    data: { label: 'lib_crypto_ext.dll', subLabel: 'Suspect Import', icon: <Database size={12}/>, iconColor: 'bg-yellow-900/50 text-neon-yellow ring-1 ring-yellow-500/50' } 
  },
  { 
    id: '3', 
    type: 'custom', 
    position: { x: 100, y: 250 }, 
    data: { label: 'crypto-js-hijacked', subLabel: 'npm package', icon: <PackageSearch size={12}/>, iconColor: 'bg-purple-900/50 text-neon-purple ring-1 ring-purple-500/50' } 
  },
  { 
    id: '4', 
    type: 'custom', 
    position: { x: 400, y: 250 }, 
    data: { label: 'pypi_stealer_module', subLabel: 'pip package', icon: <PackageSearch size={12}/>, iconColor: 'bg-purple-900/50 text-neon-purple ring-1 ring-purple-500/50' } 
  },
  { 
    id: '5', 
    type: 'custom', 
    position: { x: 250, y: 350 }, 
    data: { label: 'github.com/badactor/repo', subLabel: 'Upstream Repo', icon: <Github size={12}/>, iconColor: 'bg-slate-800 text-text-primary ring-1 ring-slate-500' } 
  },
];

const initialEdges: Edge[] = [
  { id: 'e1-2', source: '1', target: '2', animated: true, style: { stroke: '#00f0ff', strokeWidth: 2 } },
  { id: 'e2-3', source: '2', target: '3', animated: true, style: { stroke: '#334155', strokeWidth: 2 }, label: 'Dependency' },
  { id: 'e2-4', source: '2', target: '4', animated: true, style: { stroke: '#fbbf24', strokeWidth: 2 }, label: 'Dependency' },
  { id: 'e3-5', source: '3', target: '5', style: { stroke: '#ff003c', strokeWidth: 2, strokeDasharray: '5 5' }, label: 'Source (Malicious)' },
  { id: 'e4-5', source: '4', target: '5', style: { stroke: '#ff003c', strokeWidth: 2, strokeDasharray: '5 5' }, label: 'Source (Malicious)' },
];

export function AttributionGraphPane() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const { setSelectedGraphNodeId } = useInvestigationStore();
  const nodeTypes = useMemo(() => ({ custom: CustomSvelteNode }), []);

  const onNodeClick = useCallback((event: any, node: Node) => {
    setSelectedGraphNodeId(node.id);
  }, [setSelectedGraphNodeId]);

  const onPaneClick = useCallback(() => {
    setSelectedGraphNodeId(null);
  }, [setSelectedGraphNodeId]);

  return (
    <div className="h-full flex flex-col bg-surface border-border overflow-hidden">
      <div className="pane-header flex justify-between items-center z-10 w-full relative">
        <div className="flex items-center space-x-2">
          <Network className="w-4 h-4 text-neon-cyan" />
          <span>Supply Chain Attribution Graph</span>
        </div>
      </div>
      
      <div className="flex-1 relative bg-[#020617]">
        <div className="absolute inset-0 pointer-events-none bg-cyber-grid opacity-30 z-0 mix-blend-screen" />
        
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          onPaneClick={onPaneClick}
          nodeTypes={nodeTypes}
          connectionMode={ConnectionMode.Loose}
          fitView
          className="z-10"
        >
          <Background color="#1e293b" gap={16} size={1} />
          <Controls 
            className="bg-[#0f172a] border-[#334155] fill-slate-300"
            style={{ display: 'flex', flexDirection: 'column' }}
          />
        </ReactFlow>
      </div>
    </div>
  );
}
