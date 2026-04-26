import { create } from 'zustand';

export type AgentStepStatus = 'pending' | 'loading' | 'success' | 'error';

export interface AgentStep {
  id: string;
  name: string;
  status: AgentStepStatus;
  timestamp?: string;
  details?: string;
}

interface InvestigationState {
  // Session metadata
  analysisState: 'idle' | 'analyzing' | 'complete' | 'error';
  finalReport: any | null;
  fileHash: string;
  setFileHash: (hash: string) => void;
  fileSize: string;
  threatScore: number;
  liveStatus: string;
  setLiveStatus: (status: string) => void;
  setFinalReport: (report: any) => void;
  
  // Selected contexts for cross-pane interaction
  selectedGraphNodeId: string | null;
  setSelectedGraphNodeId: (id: string | null) => void;

  // Agent Timeline
  agentSteps: AgentStep[];
  updateAgentStep: (id: string, status: AgentStepStatus, details?: string) => void;
  
  // App-wide command palette toggle
  isCommandPaletteOpen: boolean;
  setCommandPaletteOpen: (open: boolean) => void;
}

export const useInvestigationStore = create<InvestigationState>((set) => ({
  analysisState: 'idle',
  finalReport: null,
  fileHash: 'SHA256: 8f434346648f6b96e448b111...722f',
  setFileHash: (hash) => set({ fileHash: hash }),
  fileSize: '4.2 MB',
  threatScore: 88,
  liveStatus: 'Analysis Agent: Mapping TTPs...',
  setLiveStatus: (status) => set({ liveStatus: status }),
  setFinalReport: (report) => set({ finalReport: report }),
  
  selectedGraphNodeId: null,
  setSelectedGraphNodeId: (id) => set({ selectedGraphNodeId: id }),

  agentSteps: [
    { id: '1', name: 'Extraction Agent: Initialized', status: 'success', timestamp: '14:02:10' },
    { id: '2', name: 'File Parsing & Entropy Check', status: 'success', timestamp: '14:02:12' },
    { id: '3', name: 'Analysis Agent: Streaming...', status: 'loading', details: 'Scanning for known malicious signatures' },
    { id: '4', name: 'Attribution Agent: Pending', status: 'pending' },
    { id: '5', name: 'Detection Engineering: Pending', status: 'pending' },
  ],
  updateAgentStep: (id, status, details) => set((state) => ({
    agentSteps: state.agentSteps.map(step => 
      step.id === id ? { ...step, status, details } : step
    )
  })),

  isCommandPaletteOpen: false,
  setCommandPaletteOpen: (open) => set({ isCommandPaletteOpen: open }),
}));
