import { create } from 'zustand';
import type { FinalReport } from '../types/report';

export type AnalysisState = 'idle' | 'analyzing' | 'complete' | 'error';
export type AgentStepStatus = 'pending' | 'loading' | 'success' | 'error';

export interface AgentStep {
  id: string;
  name: string;
  status: AgentStepStatus;
  timestamp?: string;
  details?: string;
}

interface InvestigationState {
  // Session
  analysisState: AnalysisState;
  finalReport: FinalReport | null;
  fileName: string | null;
  fileSize: number | null;
  liveStatus: string;
  errorMessage: string | null;

  // Agent Timeline
  agentSteps: AgentStep[];

  // Indicator selected in the attribution graph, used to cross-highlight panes
  selectedIndicator: string | null;
  setSelectedIndicator: (indicator: string | null) => void;

  // App-wide command palette toggle
  isCommandPaletteOpen: boolean;
  setCommandPaletteOpen: (open: boolean) => void;

  // Analysis lifecycle
  startAnalysis: (fileName: string, fileSize: number) => void;
  addStatus: (agent: string, message: string) => void;
  completeAnalysis: (report: FinalReport) => void;
  failAnalysis: (message: string) => void;
  reset: () => void;
}

const IDLE_STATUS = 'Awaiting artifact';

const initialSession = {
  analysisState: 'idle' as AnalysisState,
  finalReport: null,
  fileName: null,
  fileSize: null,
  liveStatus: IDLE_STATUS,
  errorMessage: null,
  agentSteps: [] as AgentStep[],
  selectedIndicator: null,
};

const settle = (steps: AgentStep[], status: AgentStepStatus): AgentStep[] =>
  steps.map((step) => (step.status === 'loading' ? { ...step, status } : step));

export const useInvestigationStore = create<InvestigationState>((set) => ({
  ...initialSession,

  setSelectedIndicator: (indicator) => set({ selectedIndicator: indicator }),

  isCommandPaletteOpen: false,
  setCommandPaletteOpen: (open) => set({ isCommandPaletteOpen: open }),

  startAnalysis: (fileName, fileSize) => set({
    ...initialSession,
    analysisState: 'analyzing',
    fileName,
    fileSize,
    liveStatus: 'Uploading artifact...',
  }),

  addStatus: (agent, message) => set((state) => {
    const steps = state.agentSteps;
    const last = steps[steps.length - 1];
    const liveStatus = `${agent}: ${message}`;

    // Consecutive updates from one agent refine its step instead of adding rows.
    if (last && last.name === agent && last.status === 'loading') {
      return {
        liveStatus,
        agentSteps: [...steps.slice(0, -1), { ...last, details: message }],
      };
    }
    return {
      liveStatus,
      agentSteps: [
        ...settle(steps, 'success'),
        {
          id: `step-${steps.length + 1}`,
          name: agent,
          details: message,
          status: 'loading',
          timestamp: new Date().toLocaleTimeString(),
        },
      ],
    };
  }),

  completeAnalysis: (report) => set((state) => ({
    analysisState: 'complete',
    finalReport: report,
    liveStatus: 'Analysis complete',
    errorMessage: null,
    agentSteps: settle(state.agentSteps, 'success'),
  })),

  failAnalysis: (message) => set((state) => ({
    analysisState: 'error',
    liveStatus: 'Analysis failed',
    errorMessage: message,
    agentSteps: settle(state.agentSteps, 'error'),
  })),

  reset: () => set({ ...initialSession }),
}));
