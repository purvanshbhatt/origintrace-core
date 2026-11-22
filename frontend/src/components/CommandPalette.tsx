import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search } from 'lucide-react';
import { useInvestigationStore } from '../store/useInvestigationStore';
import { copyText, downloadText } from '../lib/browser';

interface Command {
  label: string;
  run: () => void;
}

export function CommandPalette() {
  const isOpen = useInvestigationStore((state) => state.isCommandPaletteOpen);
  const setOpen = useInvestigationStore((state) => state.setCommandPaletteOpen);
  const report = useInvestigationStore((state) => state.finalReport);
  const reset = useInvestigationStore((state) => state.reset);
  const navigate = useNavigate();
  const [query, setQuery] = useState('');

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen(!useInvestigationStore.getState().isCommandPaletteOpen);
      }
      if (e.key === 'Escape') {
        setOpen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [setOpen]);

  const commands = useMemo<Command[]>(() => {
    const list: Command[] = [{ label: 'New analysis', run: reset }];
    if (report) {
      const { sha256, filename } = report.features.metadata;
      const stem = (sha256 ?? filename).slice(0, 16);
      if (sha256) list.push({ label: 'Copy SHA256', run: () => void copyText(sha256) });
      list.push(
        { label: 'Copy YARA rule', run: () => void copyText(report.detections.yara_rule) },
        { label: 'Copy Sigma rule', run: () => void copyText(report.detections.sigma_rule) },
        { label: 'Download YARA rule (.yar)', run: () => downloadText(`${stem}.yar`, report.detections.yara_rule) },
        { label: 'Download Sigma rule (.yml)', run: () => downloadText(`${stem}.yml`, report.detections.sigma_rule, 'text/yaml') },
        {
          label: 'Download full report (.json)',
          run: () => downloadText(`${stem}.report.json`, JSON.stringify(report, null, 2), 'application/json'),
        },
      );
    }
    list.push(
      { label: 'Open classic dashboard', run: () => navigate('/classic') },
      { label: 'Open documentation', run: () => navigate('/docs') },
    );
    return list;
  }, [report, reset, navigate]);

  if (!isOpen) return null;

  const needle = query.trim().toLowerCase();
  const matches = commands.filter((command) => command.label.toLowerCase().includes(needle));

  const close = () => {
    setQuery('');
    setOpen(false);
  };

  const execute = (command: Command) => {
    close();
    command.run();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh] bg-background/80 backdrop-blur-sm"
      onClick={close}
    >
      <div
        role="dialog"
        aria-label="Command palette"
        className="w-full max-w-2xl bg-surface border border-border shadow-2xl rounded-xl overflow-hidden ring-1 ring-white/10"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center px-4 py-3 border-b border-border">
          <Search className="w-5 h-5 text-text-muted mr-3" />
          <input
            autoFocus
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && matches.length > 0) execute(matches[0]);
            }}
            placeholder="Type a command..."
            aria-label="Command"
            className="flex-1 bg-transparent border-none outline-none text-text-primary text-lg placeholder:text-text-muted font-sans"
          />
          <div className="text-xs text-text-muted font-mono border border-border rounded px-2 py-1">ESC</div>
        </div>
        <div className="max-h-[60vh] overflow-y-auto p-2">
          <div className="px-3 py-2 text-xs font-semibold text-text-muted uppercase tracking-wider">Commands</div>
          {matches.length === 0 ? (
            <div className="px-3 py-2 text-sm text-text-muted">No matching command.</div>
          ) : (
            <ul className="text-sm">
              {matches.map((command) => (
                <li key={command.label}>
                  <button
                    onClick={() => execute(command)}
                    className="w-full text-left px-3 py-2 hover:bg-surface-highlight rounded-lg cursor-pointer flex items-center group"
                  >
                    <span className="text-neon-cyan mr-3 font-mono opacity-50 group-hover:opacity-100">&gt;</span>
                    {command.label}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
