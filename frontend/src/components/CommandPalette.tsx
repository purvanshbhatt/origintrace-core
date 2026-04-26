import React, { useEffect } from 'react';
import { Search } from 'lucide-react';
import { useInvestigationStore } from '../../store/useInvestigationStore';
import { cn } from '../../lib/utils';

export function CommandPalette() {
  const { isCommandPaletteOpen, setCommandPaletteOpen } = useInvestigationStore();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setCommandPaletteOpen(!isCommandPaletteOpen);
      }
      if (e.key === 'Escape' && isCommandPaletteOpen) {
        setCommandPaletteOpen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isCommandPaletteOpen, setCommandPaletteOpen]);

  if (!isCommandPaletteOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh] bg-background/80 backdrop-blur-sm">
      <div className="w-full max-w-2xl bg-surface border border-border shadow-2xl rounded-xl overflow-hidden ring-1 ring-white/10">
        <div className="flex items-center px-4 py-3 border-b border-border">
          <Search className="w-5 h-5 text-text-muted mr-3" />
          <input 
            autoFocus
            type="text" 
            placeholder="Type a command or search... (e.g. > Export STIX)"
            className="flex-1 bg-transparent border-none outline-none text-text-primary text-lg placeholder:text-text-muted font-sans"
          />
          <div className="text-xs text-text-muted font-mono border border-border rounded px-2 py-1">ESC</div>
        </div>
        <div className="max-h-[60vh] overflow-y-auto p-2">
          <div className="px-3 md:py-2 text-xs font-semibold text-text-muted uppercase tracking-wider">Suggestions</div>
          <ul className="text-sm">
            <li className="px-3 py-2 hover:bg-surface-highlight rounded-lg cursor-pointer flex items-center group">
              <span className="text-neon-cyan mr-3 font-mono opacity-50 group-hover:opacity-100">&gt;</span>
              Export STIX 2.1 Bundle
            </li>
            <li className="px-3 py-2 hover:bg-surface-highlight rounded-lg cursor-pointer flex items-center group">
              <span className="text-neon-cyan mr-3 font-mono opacity-50 group-hover:opacity-100">&gt;</span>
              Filter Graph: High Confidence
            </li>
            <li className="px-3 py-2 hover:bg-surface-highlight rounded-lg cursor-pointer flex items-center group">
              <span className="text-neon-cyan mr-3 font-mono opacity-50 group-hover:opacity-100">&gt;</span>
              View Execution Timeline
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
