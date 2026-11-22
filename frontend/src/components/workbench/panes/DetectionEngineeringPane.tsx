import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Terminal, Copy, DownloadCloud, CheckCircle2 } from 'lucide-react';
import { cn } from '../../../lib/utils';
import { motion, AnimatePresence } from 'framer-motion';
import { useInvestigationStore } from '../../../store/useInvestigationStore';
import { copyText, downloadText } from '../../../lib/browser';

type RuleKind = 'yara' | 'sigma';

// Rule text embeds strings taken from the analysed (hostile) sample, so it is
// highlighted by building React nodes — never by injecting HTML.
const YARA_TOKENS = /(?<string>"(?:[^"\\\n]|\\.)*")|(?<variable>\$\w*\*?)|(?<keyword>\b(?:rule|meta|strings|condition|import|and|or|not|any|all|of|them|filesize|ascii|wide|nocase|true|false|uint16|uint32)\b)|(?<number>\b0x[0-9a-fA-F]+\b|\b\d+\b)/g;
const SIGMA_TOKENS = /(?<keyword>^[ \t-]*[\w|.-]+:)|(?<string>'(?:[^'\n]|'')*')/gm;

const TOKEN_CLASS: Record<string, string> = {
  string: 'text-neon-yellow',
  variable: 'text-neon-green',
  keyword: 'text-neon-purple font-bold',
  number: 'text-neon-cyan',
};

function highlight(text: string, kind: RuleKind): ReactNode[] {
  const pattern = kind === 'yara' ? YARA_TOKENS : SIGMA_TOKENS;
  const nodes: ReactNode[] = [];
  let cursor = 0;

  for (const match of text.matchAll(pattern)) {
    const start = match.index ?? 0;
    if (start > cursor) nodes.push(text.slice(cursor, start));
    const tokenType = Object.entries(match.groups ?? {}).find(([, value]) => value !== undefined)?.[0] ?? 'string';
    nodes.push(<span key={start} className={TOKEN_CLASS[tokenType]}>{match[0]}</span>);
    cursor = start + match[0].length;
  }
  if (cursor < text.length) nodes.push(text.slice(cursor));
  return nodes;
}

export function DetectionEngineeringPane() {
  const [activeTab, setActiveTab] = useState<RuleKind>('yara');
  const [copied, setCopied] = useState(false);
  const report = useInvestigationStore((state) => state.finalReport);

  const yaraRule = report?.detections.yara_rule ?? '';
  const sigmaRule = report?.detections.sigma_rule ?? '';
  const activeContent = activeTab === 'yara' ? yaraRule : sigmaRule;
  const highlighted = useMemo(() => highlight(activeContent, activeTab), [activeContent, activeTab]);

  const handleCopy = async () => {
    if (!activeContent || !(await copyText(activeContent))) return;
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!report || !activeContent) return;
    const { sha256, filename } = report.features.metadata;
    const stem = (sha256 ?? filename).slice(0, 16);
    if (activeTab === 'yara') downloadText(`${stem}.yar`, activeContent);
    else downloadText(`${stem}.yml`, activeContent, 'text/yaml');
  };

  const tabClass = (tab: RuleKind) => cn(
    "px-4 py-2 text-xs font-semibold uppercase tracking-wider flex items-center border-r border-border transition-colors outline-none",
    activeTab === tab ? "bg-[#0f172a] text-neon-cyan shadow-[inset_0_-2px_0_0_#00f0ff]" : "bg-transparent hover:bg-surface text-text-muted"
  );

  return (
    <div className="h-full flex flex-col bg-surface overflow-hidden border-t border-border/50">
      <div className="pane-header !p-0 pr-2 flex items-center justify-between bg-surface-highlight border-b border-border/70">
        <div className="flex">
          <button className={tabClass('yara')} onClick={() => setActiveTab('yara')}>
            <Terminal className="w-4 h-4 mr-2" />
            YARA
          </button>
          <button className={tabClass('sigma')} onClick={() => setActiveTab('sigma')}>
            <Terminal className="w-4 h-4 mr-2" />
            Sigma
          </button>
        </div>

        <div className="flex items-center space-x-2 pr-2">
          {report && (
            <span className="text-[10px] text-text-muted normal-case hidden md:inline">engine: {report.detections.engine}</span>
          )}
          <button onClick={handleCopy} disabled={!activeContent} className="flex items-center px-3 py-1 bg-background hover:bg-surface-highlight border border-border rounded text-[10px] text-text-secondary transition-colors group relative disabled:opacity-40">
            <AnimatePresence mode="wait">
              {copied ? (
                <motion.div key="check" initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }}>
                  <CheckCircle2 className="w-3 h-3 text-neon-green" />
                </motion.div>
              ) : (
                <motion.div key="copy" initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }}>
                  <Copy className="w-3 h-3 group-hover:text-neon-cyan transition-colors" />
                </motion.div>
              )}
            </AnimatePresence>
            <span className="ml-1 uppercase tracking-widest">{copied ? 'Copied' : 'Copy'}</span>
          </button>

          <button onClick={handleDownload} disabled={!activeContent} className="flex items-center px-3 py-1 bg-background hover:bg-surface-highlight border border-border rounded text-[10px] text-text-secondary transition-colors group disabled:opacity-40">
            <DownloadCloud className="w-3 h-3 group-hover:text-neon-cyan transition-colors" />
            <span className="ml-1 uppercase tracking-widest">Download</span>
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto bg-[#090e17] p-4 relative group custom-scrollbar">
        {activeContent ? (
          <pre className="font-mono text-sm leading-relaxed text-text-primary/90">
            <code className="block whitespace-pre-wrap break-words selection:bg-neon-cyan/30 selection:text-white">
              {highlighted}
            </code>
          </pre>
        ) : (
          <div className="h-full flex items-center justify-center text-sm text-text-muted">No detection rule available.</div>
        )}
      </div>
    </div>
  );
}
