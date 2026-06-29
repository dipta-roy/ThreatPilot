import { useState } from 'react';
import { useDesignerStore } from '../store/useDesignerStore';
import { generateAsciiArchitecture } from '../utils/asciiGenerator';
import { generateMermaidDiagram } from '../utils/mermaidGenerator';
import { FileText, Code2, Presentation, Copy, Check } from 'lucide-react';

export default function ExportOutputPanel() {
  const { nodes, edges, assets } = useDesignerStore();
  const [activeTab, setActiveTab] = useState<'ascii' | 'mermaid' | 'summary'>('summary');
  const [copied, setCopied] = useState(false);

  const asciiText = generateAsciiArchitecture(nodes, edges);
  const mermaidText = generateMermaidDiagram(nodes, edges);

  // Calculate statistics
  const components = nodes.filter((n) => n.type === 'componentNode');
  const processes = components.filter((c) => c.data.element_type === 'Process');
  const entities = components.filter((c) => c.data.element_type === 'Entity');
  const stores = components.filter((c) => c.data.element_type === 'Data Store');
  const boundaries = nodes.filter((n) => n.type === 'boundaryNode');

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="h-full flex flex-col select-none">
      {/* Tabs Header */}
      <div className="flex border-b border-slate-200 dark:border-border bg-slate-100 dark:bg-slate-950 p-2 gap-1.5 shrink-0">
        <button
          onClick={() => setActiveTab('summary')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition ${
            activeTab === 'summary'
              ? 'bg-white dark:bg-slate-900 text-primary-600 dark:text-primary-400 border border-slate-200 dark:border-border'
              : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <Presentation className="w-3.5 h-3.5" />
          Summary
        </button>
        <button
          onClick={() => setActiveTab('ascii')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition ${
            activeTab === 'ascii'
              ? 'bg-white dark:bg-slate-900 text-primary-600 dark:text-primary-400 border border-slate-200 dark:border-border'
              : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          ASCII Art
        </button>
        <button
          onClick={() => setActiveTab('mermaid')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition ${
            activeTab === 'mermaid'
              ? 'bg-white dark:bg-slate-900 text-primary-600 dark:text-primary-400 border border-slate-200 dark:border-border'
              : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <Code2 className="w-3.5 h-3.5" />
          Mermaid
        </button>
      </div>

      {/* Tab Contents */}
      <div className="flex-1 overflow-y-auto relative">
        {/* SUMMARY TAB */}
        {activeTab === 'summary' && (
          <div className="p-4 flex flex-col gap-4">
            <h4 className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-widest border-b border-slate-200 dark:border-border pb-1.5">
              Component Classifications
            </h4>
            <div className="flex flex-col gap-2">
              <div className="flex justify-between items-center bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border/30 p-2 px-3 rounded-lg text-xs">
                <span className="text-slate-500 dark:text-slate-400">Processes</span>
                <span className="font-bold text-emerald-600 dark:text-emerald-400">{processes.length}</span>
              </div>
              <div className="flex justify-between items-center bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border/30 p-2 px-3 rounded-lg text-xs">
                <span className="text-slate-500 dark:text-slate-400">Entities (Users/External)</span>
                <span className="font-bold text-blue-600 dark:text-blue-400">{entities.length}</span>
              </div>
              <div className="flex justify-between items-center bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border/30 p-2 px-3 rounded-lg text-xs">
                <span className="text-slate-500 dark:text-slate-400">Data Stores (DB/Cache)</span>
                <span className="font-bold text-amber-600 dark:text-amber-400">{stores.length}</span>
              </div>
              <div className="flex justify-between items-center bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border/30 p-2 px-3 rounded-lg text-xs">
                <span className="text-slate-500 dark:text-slate-400">Global Security Assets</span>
                <span className="font-bold text-purple-600 dark:text-purple-400">{assets.length}</span>
              </div>
            </div>

            <h4 className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-widest border-b border-slate-200 dark:border-border pb-1.5 mt-2">
              Project Infrastructure Statistics
            </h4>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border p-3 rounded-lg flex flex-col gap-1">
                <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase">Components</span>
                <span className="text-xl font-bold text-slate-800 dark:text-text">{components.length}</span>
              </div>
              <div className="bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border p-3 rounded-lg flex flex-col gap-1">
                <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase">Trust Boundaries</span>
                <span className="text-xl font-bold text-slate-800 dark:text-text">{boundaries.length}</span>
              </div>
              <div className="bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border p-3 rounded-lg flex flex-col gap-1 col-span-2">
                <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase">Data Flows</span>
                <span className="text-xl font-bold text-slate-800 dark:text-text">{edges.length}</span>
              </div>
            </div>
          </div>
        )}

        {/* ASCII TAB */}
        {activeTab === 'ascii' && (
          <div className="h-full flex flex-col">
            <button
              onClick={() => copyToClipboard(asciiText)}
              className="absolute top-3 right-3 p-1.5 bg-slate-100 dark:bg-slate-900 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-200 dark:border-border text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded transition"
              title="Copy to clipboard"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
            <pre className="p-4 font-mono text-[10px] text-slate-700 dark:text-slate-300 leading-relaxed overflow-x-auto whitespace-pre">
              {asciiText}
            </pre>
          </div>
        )}

        {/* MERMAID TAB */}
        {activeTab === 'mermaid' && (
          <div className="h-full flex flex-col">
            <button
              onClick={() => copyToClipboard(mermaidText)}
              className="absolute top-3 right-3 p-1.5 bg-slate-100 dark:bg-slate-900 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-200 dark:border-border text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded transition"
              title="Copy to clipboard"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
            <pre className="p-4 font-mono text-[10px] text-slate-700 dark:text-slate-300 leading-relaxed overflow-x-auto whitespace-pre select-all bg-slate-100 dark:bg-slate-950/30 rounded m-2 border border-slate-200 dark:border-border">
              {mermaidText}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
