import React from 'react';
import { CheckCircle2, ChevronRight, Loader2, Clock } from 'lucide-react';
import { useInvestigationStore } from '../../store/useInvestigationStore';
import { cn } from '../../lib/utils';
import { motion, AnimatePresence } from 'framer-motion';

export function AgentTimeline() {
  const { agentSteps } = useInvestigationStore();

  return (
    <div className="w-72 bg-surface border-l border-border h-full flex flex-col shrink-0">
      <div className="pane-header">
        <span>Agent Operations</span>
        <span className="text-neon-cyan/70 text-[10px] animate-pulse">Live</span>
      </div>
      
      <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">
        <div className="relative">
          {/* Vertical Timeline Line */}
          <div className="absolute left-[15px] top-4 bottom-4 w-px bg-border/50"></div>
          
          <div className="space-y-6">
            <AnimatePresence>
              {agentSteps.map((step, idx) => {
                const isSuccess = step.status === 'success';
                const isLoading = step.status === 'loading';
                const isPending = step.status === 'pending';

                return (
                  <motion.div 
                    key={step.id} 
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="relative flex items-start group"
                  >
                    {/* Icon */}
                    <div className="flex-shrink-0 z-10 w-8 h-8 rounded-full bg-background border flex items-center justify-center transition-colors
                      ${isSuccess ? 'border-neon-green/50 text-neon-green' : 
                        isLoading ? 'border-neon-cyan/50 text-neon-cyan ring-1 ring-cyan-500/30' : 
                        'border-border text-text-muted'}">
                      {isSuccess && <CheckCircle2 className="w-4 h-4" />}
                      {isLoading && <Loader2 className="w-4 h-4 animate-spin" />}
                      {isPending && <Clock className="w-4 h-4" />}
                    </div>

                    {/* Content */}
                    <div className="ml-4 flex-1">
                      <div className="flex items-center justify-between">
                        <span className={cn(
                          "text-sm font-semibold tracking-wide",
                          isSuccess ? "text-text-primary" : 
                          isLoading ? "text-neon-cyan drop-shadow-[0_0_8px_rgba(0,240,255,0.4)]" : "text-text-muted"
                        )}>
                          {step.name}
                        </span>
                        {step.timestamp && (
                          <span className="text-[10px] font-mono text-text-muted">
                            {step.timestamp}
                          </span>
                        )}
                      </div>
                      
                      {step.details && (
                        <motion.div 
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          className="mt-2 text-xs text-text-secondary bg-surface-highlight p-2 rounded border border-border/50 break-words"
                        >
                          <ChevronRight className="w-3 h-3 inline mr-1 text-neon-cyan" />
                          {step.details}
                        </motion.div>
                      )}
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}
