import React, { useEffect } from 'react';
import { useDesignerStore, parseCVSSVector, generateCVSSVector, calculateCVSSBaseScore } from './store/useDesignerStore';
import Canvas from './components/Canvas';
import PropertiesPanel from './components/PropertiesPanel';
import ValidationPanel from './components/ValidationPanel';
import ExportOutputPanel from './components/ExportOutputPanel';
import JiraSettingsModal from './components/JiraSettingsModal';
import AddThreatModal from './components/AddThreatModal';
import AddRiskModal from './components/AddRiskModal';
import AddVulnerabilityModal from './components/AddVulnerabilityModal';
import AddMitigationModal from './components/AddMitigationModal';
import { ShieldAlert, Save, RefreshCw, Layers, Sun, Moon, Brain, Settings, X, Info, Download, Search, FileSpreadsheet, FileCode, Edit, Trash2, Sparkles, Shield, Briefcase, Plus } from 'lucide-react';

const renderInlineBold = (text: string) => {
  const parts = text.split('**');
  return parts.map((part, i) => {
    if (i % 2 === 1) {
      return <strong key={i} className="font-bold text-slate-950 dark:text-white">{part}</strong>;
    }
    return part;
  });
};

const renderMarkdown = (md: string) => {
  const lines = md.split('\n');
  return (
    <div className="space-y-3 leading-relaxed text-slate-700 dark:text-slate-300">
      {lines.map((line, idx) => {
        const trimmed = line.trim();

        // Horizontal rule
        if (trimmed === '---') {
          return <hr key={idx} className="border-t border-slate-200 dark:border-border/30 my-4" />;
        }

        // Headers
        if (trimmed.startsWith('# ')) {
          return <h1 key={idx} className="text-base font-extrabold text-slate-900 dark:text-white mt-4 mb-2">{trimmed.substring(2)}</h1>;
        }
        if (trimmed.startsWith('## ')) {
          return <h2 key={idx} className="text-sm font-bold text-slate-900 dark:text-white mt-4 mb-2">{trimmed.substring(3)}</h2>;
        }
        if (trimmed.startsWith('### ')) {
          return <h3 key={idx} className="text-xs font-bold text-slate-900 dark:text-white mt-3 mb-1.5">{trimmed.substring(4)}</h3>;
        }
        if (trimmed.startsWith('#### ')) {
          return <h4 key={idx} className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mt-2 mb-1">{trimmed.substring(5)}</h4>;
        }

        // Bullet points
        if (trimmed.startsWith('* ') || trimmed.startsWith('- ')) {
          const content = trimmed.substring(2);
          return (
            <li key={idx} className="ml-4 list-disc pl-1 text-xs">
              {renderInlineBold(content)}
            </li>
          );
        }

        // Ordered lists
        const matchOrdered = trimmed.match(/^(\d+)\.\s+(.*)$/);
        if (matchOrdered) {
          return (
            <li key={idx} className="ml-4 list-decimal pl-1 text-xs">
              {renderInlineBold(matchOrdered[2])}
            </li>
          );
        }

        // Normal paragraph
        if (trimmed === '') {
          return <div key={idx} className="h-1" />;
        }

        return <p key={idx} className="text-xs">{renderInlineBold(line)}</p>;
      })}
    </div>
  );
};

export default function App() {
  const {
    projectName,
    fetchProject,
    fetchThreatLedger,
    saveProject,
    hasUnsavedChanges,
    isSaving,
    saveError,
    isLoading,
    isDarkMode,
    toggleTheme,
    showRiskInCanvas,
    toggleRiskInCanvas,
    nodes,
    threats,
    updateThreat,
    deleteThreat,
    vulnerabilities,
    updateVulnerability,
    deleteVulnerability,
    mitigationRequirements,
    updateMitigationRequirement,
    deleteMitigationRequirement
  } = useDesignerStore();

  const uniqueThreats = Array.from(new Map((threats || []).map(t => [t.threat_id, t])).values());
  const uniqueVulns = Array.from(new Map((vulnerabilities || []).map(v => [v.vulnerability_id, v])).values());

  const [currentView, setCurrentView] = React.useState<'canvas' | 'ledger' | 'reports'>('canvas');
  const [ledgerSearch, setLedgerSearch] = React.useState('');
  const [ledgerTab, setLedgerTab] = React.useState<'threats' | 'vulnerabilities' | 'assessment' | 'mitigations'>('threats');
  const [editingMitId, setEditingMitId] = React.useState<string | null>(null);
  const [editingThreat, setEditingThreat] = React.useState<any | null>(null);
  const [editingVuln, setEditingVuln] = React.useState<any | null>(null);
  const [generatingReasoningVulnId, setGeneratingReasoningVulnId] = React.useState<string | null>(null);
  const [generatingReasoningMitId, setGeneratingReasoningMitId] = React.useState<string | null>(null);
  const [generatingReasoningThreatId, setGeneratingReasoningThreatId] = React.useState<string | null>(null);
  const [reasoningModalContent, setReasoningModalContent] = React.useState<string | null>(null);
  const [reasoningModalTitle, setReasoningModalTitle] = React.useState<string | null>(null);
  const [selectedMatrixCell, setSelectedMatrixCell] = React.useState<{ likelihood: number, impactScore: number } | null>(null);

  const [selectedThreatIds, setSelectedThreatIds] = React.useState<Set<string>>(new Set());
  const [selectedVulnIds, setSelectedVulnIds] = React.useState<Set<string>>(new Set());
  const [selectedRiskIds, setSelectedRiskIds] = React.useState<Set<string>>(new Set());
  const [selectedMitIds, setSelectedMitIds] = React.useState<Set<string>>(new Set());

  const [isBusinessContextModalOpen, setIsBusinessContextModalOpen] = React.useState(false);

  const [isAddingThreat, setIsAddingThreat] = React.useState(false);
  const [isAddingRisk, setIsAddingRisk] = React.useState(false);
  const [isAddingVuln, setIsAddingVuln] = React.useState(false);
  const [isAddingMitigation, setIsAddingMitigation] = React.useState(false);
  const [isJiraSettingsOpen, setIsJiraSettingsOpen] = React.useState(false);
  const [isSyncingAll, setIsSyncingAll] = React.useState(false);
  const [syncingReqId, setSyncingReqId] = React.useState<string | null>(null);

  const [promptConfig, setPromptConfig] = React.useState({
    risk_preference: 'Medium',
    security_posture: 'Standard',
    compliance_priority: '',
    industry_context: '',
    business_context_policy: '',
    custom_prompt: ''
  });

  const [isNarrativeModalOpen, setIsNarrativeModalOpen] = React.useState(false);
  const [narrativeText, setNarrativeText] = React.useState<string | null>(null);
  const [isGeneratingNarrative, setIsGeneratingNarrative] = React.useState(false);

  const getSelectedCount = () => {
    switch (ledgerTab) {
      case 'threats': return selectedThreatIds.size;
      case 'vulnerabilities': return selectedVulnIds.size;
      case 'assessment': return selectedRiskIds.size;
      case 'mitigations': return selectedMitIds.size;
      default: return 0;
    }
  };

  const handleBulkDelete = () => {
    if (ledgerTab === 'threats') {
      if (confirm(`Delete ${selectedThreatIds.size} threats?`)) {
        Array.from(selectedThreatIds).forEach(id => deleteThreat(id));
        setSelectedThreatIds(new Set());
      }
    } else if (ledgerTab === 'vulnerabilities') {
      if (confirm(`Delete ${selectedVulnIds.size} vulnerabilities?`)) {
        Array.from(selectedVulnIds).forEach(id => deleteVulnerability(id));
        setSelectedVulnIds(new Set());
      }
    } else if (ledgerTab === 'assessment') {
      if (confirm(`Delete ${selectedRiskIds.size} threats from risk assessment?`)) {
        Array.from(selectedRiskIds).forEach(id => deleteThreat(id));
        setSelectedRiskIds(new Set());
      }
    } else if (ledgerTab === 'mitigations') {
      if (confirm(`Delete ${selectedMitIds.size} mitigations?`)) {
        Array.from(selectedMitIds).forEach(id => deleteMitigationRequirement(id));
        setSelectedMitIds(new Set());
      }
    }
  };
  // Maps CVSS score (0-10) to impact score 1-5 matching desktop's score_to_impact_score
  const scoreToImpactScore = (cvss: number): number => {
    if (cvss >= 9.0) return 5;
    if (cvss >= 7.0) return 4;
    if (cvss >= 4.0) return 3;
    if (cvss >= 2.0) return 2;
    return 1;
  };

  const likelihoodLabels: Record<number, string> = { 5: 'Certain (5)', 4: 'Likely (4)', 3: 'Possible (3)', 2: 'Unlikely (2)', 1: 'Rare (1)' };
  const impactLabels: Record<number, string> = { 1: 'Low (1)', 2: 'Minor (2)', 3: 'Mid (3)', 4: 'Major (4)', 5: 'Crit (5)' };

  const getThreatsForCell = (likelihood: number, impactScore: number) => {
    return uniqueThreats.filter(t => {
      const tLikelihood = t.likelihood || 3;
      const tImpact = scoreToImpactScore(t.cvss_score || 0);
      return tLikelihood === likelihood && tImpact === impactScore;
    });
  };

  const getCellColor = (likelihood: number, impactScore: number, count: number) => {
    const riskScore = likelihood * impactScore;
    const active = selectedMatrixCell?.likelihood === likelihood && selectedMatrixCell?.impactScore === impactScore;
    const emptyClass = count === 0 ? 'opacity-40 border-dashed' : '';

    if (riskScore >= 15) {
      return `${emptyClass} bg-rose-600/25 text-rose-600 dark:bg-rose-600/15 border-rose-500/30 hover:bg-rose-600/35 ${active ? 'ring-2 ring-rose-500 ring-offset-2 dark:ring-offset-slate-900' : ''}`;
    }
    if (riskScore >= 10) {
      return `${emptyClass} bg-orange-500/20 text-orange-600 dark:bg-orange-500/10 border-orange-500/30 hover:bg-orange-500/30 ${active ? 'ring-2 ring-orange-500 ring-offset-2 dark:ring-offset-slate-900' : ''}`;
    }
    if (riskScore >= 6) {
      return `${emptyClass} bg-amber-500/20 text-amber-600 dark:bg-amber-500/10 border-amber-500/30 hover:bg-amber-500/30 ${active ? 'ring-2 ring-amber-500 ring-offset-2 dark:ring-offset-slate-900' : ''}`;
    }
    if (riskScore >= 3) {
      return `${emptyClass} bg-yellow-500/20 text-yellow-600 dark:bg-yellow-500/10 border-yellow-500/30 hover:bg-yellow-500/30 ${active ? 'ring-2 ring-yellow-500 ring-offset-2 dark:ring-offset-slate-900' : ''}`;
    }
    return `${emptyClass} bg-emerald-500/20 text-emerald-600 dark:bg-emerald-500/10 border-emerald-500/30 hover:bg-emerald-500/30 ${active ? 'ring-2 ring-emerald-500 ring-offset-2 dark:ring-offset-slate-900' : ''}`;
  };

  const runThreatAIAnalysis = async (threatId: string) => {
    setGeneratingReasoningThreatId(threatId);
    try {
      await useDesignerStore.getState().saveProject(true);
      const res = await fetch('/api/ai/reason', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threat_id: threatId })
      });
      if (res.ok) {
        const data = await res.json();
        updateThreat(threatId, { reasoning: data.reasoning });
        setReasoningModalTitle('Threat XAI Technical Reasoning');
        setReasoningModalContent(data.reasoning);
      } else {
        const err = await res.json();
        alert(err.error || 'Failed to generate reasoning');
      }
    } catch (e) {
      console.error(e);
      alert('Error generating reasoning');
    } finally {
      setGeneratingReasoningThreatId(null);
    }
  };

  const runVulnerabilityAIAnalysis = async (vulnId: string) => {
    setGeneratingReasoningVulnId(vulnId);
    try {
      await useDesignerStore.getState().saveProject(true);
      const res = await fetch('/api/ai/reason', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerability_id: vulnId })
      });
      if (res.ok) {
        const data = await res.json();
        updateVulnerability(vulnId, { reasoning: data.reasoning });
        setReasoningModalTitle('Vulnerability XAI Technical Reasoning');
        setReasoningModalContent(data.reasoning);
      } else {
        const err = await res.json();
        alert(err.error || 'Failed to generate reasoning');
      }
    } catch (e) {
      console.error(e);
      alert('Error generating reasoning');
    } finally {
      setGeneratingReasoningVulnId(null);
    }
  };

  const runMitigationAIAnalysis = async (reqId: string) => {
    setGeneratingReasoningMitId(reqId);
    try {
      await useDesignerStore.getState().saveProject(true);
      const res = await fetch('/api/ai/reason', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ req_id: reqId })
      });
      if (res.ok) {
        const data = await res.json();
        updateMitigationRequirement(reqId, { reasoning: data.reasoning });
        setReasoningModalTitle('Mitigation Control XAI Reasoning');
        setReasoningModalContent(data.reasoning);
      } else {
        const err = await res.json();
        alert(err.error || 'Failed to generate reasoning');
      }
    } catch (e) {
      console.error(e);
      alert('Error generating reasoning');
    } finally {
      setGeneratingReasoningMitId(null);
    }
  };

  const [mitigationsState, setMitigationsState] = React.useState({
    status: 'idle',
    progress: '',
    error: null as string | null
  });

  const [isConfigModalOpen, setIsConfigModalOpen] = React.useState(false);
  const [isAnalysisModalOpen, setIsAnalysisModalOpen] = React.useState(false);

  const [providerType, setProviderType] = React.useState('ollama');
  const [endpointUrl, setEndpointUrl] = React.useState('http://localhost:11434');
  const [modelName, setModelName] = React.useState('');
  const [geminiApiKey, setGeminiApiKey] = React.useState('');
  const [maxTokens, setMaxTokens] = React.useState<number | ''>(16384);
  const [ollamaModels, setOllamaModels] = React.useState<string[]>([]);
  const [ollamaModelsLoading, setOllamaModelsLoading] = React.useState(false);

  const fetchOllamaModels = async () => {
    setOllamaModelsLoading(true);
    try {
      const res = await fetch('/api/ai/ollama/models');
      if (res.ok) {
        const data = await res.json();
        const models = data.models || [];
        setOllamaModels(models);
        setModelName(current => {
          if (models.length > 0 && !models.includes(current)) {
            return models[0];
          }
          return current;
        });
      }
    } catch (e) {
      console.error("Failed to fetch Ollama models", e);
    } finally {
      setOllamaModelsLoading(false);
    }
  };

  const [analysisMode, setAnalysisMode] = React.useState('STRIDE');
  const [iterations, setIterations] = React.useState(1);

  const handleSyncJira = async (reqId?: string) => {
    if (reqId) setSyncingReqId(reqId);
    else setIsSyncingAll(true);
    try {
      const res = await fetch('/api/jira/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reqId ? { req_id: reqId } : {})
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Sync failed');
      await fetchProject();
    } catch (e: any) {
      alert(e.message);
    } finally {
      if (reqId) setSyncingReqId(null);
      else setIsSyncingAll(false);
    }
  };

  const [analysisState, setAnalysisState] = React.useState<{
    status: string;
    current_iteration: number;
    total_iterations: number;
    current_segment: number;
    total_segments: number;
    new_threats: number;
    error: string | null;
  }>({
    status: 'idle',
    current_iteration: 0,
    total_iterations: 0,
    current_segment: 0,
    total_segments: 0,
    new_threats: 0,
    error: null,
  });

  const [showCompletionMessage, setShowCompletionMessage] = React.useState(false);

  const fetchAIConfig = async () => {
    try {
      const res = await fetch('/api/ai/config');
      if (res.ok) {
        const data = await res.json();
        setProviderType(data.provider_type || 'ollama');
        setEndpointUrl(data.endpoint_url || 'http://localhost:11434');
        setModelName(data.model_name || '');
        setGeminiApiKey(data.gemini_api_key || '');
        setMaxTokens(data.max_tokens || 16384);
        // Auto-fetch ollama models if provider is ollama
        if ((data.provider_type || 'ollama') === 'ollama') {
          fetchOllamaModels();
        }
      }
    } catch (e) {
      console.error("Failed to fetch AI config", e);
    }
  };

  const saveAIConfig = async () => {
    try {
      const res = await fetch('/api/ai/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider_type: providerType,
          endpoint_url: endpointUrl,
          model_name: modelName,
          gemini_api_key: geminiApiKey,
          max_tokens: maxTokens ? Number(maxTokens) : 16384
        })
      });
      if (res.ok) {
        setIsConfigModalOpen(false);
      }
    } catch (e) {
      console.error("Failed to save AI config", e);
    }
  };

  const fetchPromptConfig = async () => {
    try {
      const response = await fetch('/api/project/prompt_config');
      if (response.ok) {
        const data = await response.json();
        setPromptConfig({
          risk_preference: data.risk_preference || 'Medium',
          security_posture: data.security_posture || 'Standard',
          compliance_priority: data.compliance_priority || '',
          industry_context: data.industry_context || '',
          business_context_policy: data.business_context_policy || '',
          custom_prompt: data.custom_prompt || ''
        });
      }
    } catch (e) {
      console.error("Failed to fetch prompt config", e);
    }
  };

  const savePromptConfig = async () => {
    try {
      const res = await fetch('/api/project/prompt_config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(promptConfig)
      });
      if (res.ok) {
        setIsBusinessContextModalOpen(false);
      }
    } catch (e) {
      console.error("Failed to save prompt config", e);
    }
  };

  const runAIAnalysis = async () => {
    try {
      const res = await fetch('/api/ai/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: analysisMode,
          iterations: iterations
        })
      });
      if (res.ok) {
        setIsAnalysisModalOpen(false);
        setShowCompletionMessage(false);
        setAnalysisState(prev => ({ ...prev, status: 'running', error: null }));
        useDesignerStore.getState().setAnalyzingElements([], []);
      } else {
        const errData = await res.json();
        alert(errData.error || 'Failed to start AI analysis');
      }
    } catch (e) {
      console.error("Failed to run AI analysis", e);
    }
  };

  useEffect(() => {
    fetchAIConfig();

    const handleStartGlobalAI = () => setAnalysisState(prev => ({ ...prev, status: 'running', error: null }));
    window.addEventListener('start-ai-analysis', handleStartGlobalAI);
    return () => window.removeEventListener('start-ai-analysis', handleStartGlobalAI);
  }, []);

  useEffect(() => {
    let intervalId: any = null;
    let currentNewThreats = 0;
    if (analysisState.status === 'running') {
      intervalId = setInterval(async () => {
        try {
          const res = await fetch('/api/ai/status');
          if (res.ok) {
            const data = await res.json();
            setAnalysisState(data);
            useDesignerStore.getState().setAnalyzingElements(data.analyzing_node_ids || [], data.analyzing_edge_ids || []);
            if (data.new_threats > currentNewThreats) {
              currentNewThreats = data.new_threats;
              fetchThreatLedger();
            }
            if (data.status === 'completed') {
              clearInterval(intervalId);
              useDesignerStore.getState().setAnalyzingElements([], []);
              setShowCompletionMessage(true);
              fetchProject();
            } else if (data.status === 'failed') {
              clearInterval(intervalId);
              useDesignerStore.getState().setAnalyzingElements([], []);
            }
          }
        } catch (e) {
          console.error("Failed to fetch AI status", e);
        }
      }, 2000);
    }
    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [analysisState.status, fetchProject, fetchThreatLedger]);

  useEffect(() => {
    let intervalId: any;
    if (mitigationsState.status === 'running') {
      intervalId = setInterval(async () => {
        try {
          const res = await fetch('/api/ai/mitigations/status');
          if (res.ok) {
            const data = await res.json();
            setMitigationsState({
              status: data.status,
              progress: data.progress,
              error: data.error || null
            });
            if (data.status === 'completed') {
              clearInterval(intervalId);
              fetchProject();
            } else if (data.status === 'failed') {
              clearInterval(intervalId);
            }
          }
        } catch (e) {
          console.error("Failed to fetch mitigations status", e);
        }
      }, 2000);
    }
    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [mitigationsState.status, fetchProject]);

  const triggerMitigationsReview = async () => {
    setMitigationsState({ status: 'running', progress: 'Starting Mitigation AI review...', error: null });
    try {
      const res = await fetch('/api/ai/mitigations', { method: 'POST' });
      if (!res.ok) {
        const err = await res.json();
        setMitigationsState({ status: 'failed', progress: '', error: err.error || 'Failed to start mitigations review' });
      }
    } catch (e: any) {
      setMitigationsState({ status: 'failed', progress: '', error: e.message || 'Error occurred' });
    }
  };

  const handleGenerateNarrative = async () => {
    setIsGeneratingNarrative(true);
    setNarrativeText(null);
    setIsNarrativeModalOpen(true);
    try {
      const res = await fetch('/api/ai/narrative', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          components: nodes.filter(n => n.type === 'componentNode').map(n => n.data),
          boundaries: nodes.filter(n => n.type === 'boundaryNode').map(n => n.data),
          flows: useDesignerStore.getState().edges.map(e => ({
            id: e.id,
            source_id: e.source,
            target_id: e.target,
            name: e.label || 'Flow',
            protocol: e.data?.protocol || 'HTTPS',
            is_bidirectional: e.data?.isBidirectional || false
          })),
          assets: useDesignerStore.getState().assets || []
        })
      });
      if (res.ok) {
        const data = await res.json();
        setNarrativeText(data.narrative);
      } else {
        const data = await res.json();
        alert(data.error || 'Failed to generate narrative');
        setIsNarrativeModalOpen(false);
      }
    } catch (e) {
      console.error(e);
      alert('Error connecting to backend');
      setIsNarrativeModalOpen(false);
    } finally {
      setIsGeneratingNarrative(false);
    }
  };

  // Load project on mount
  useEffect(() => {
    fetchProject();
  }, [fetchProject]);

  // Poll for project changes (e.g. when user opens a new project in desktop app)
  useEffect(() => {
    let errorCount = 0;
    const intervalId = setInterval(async () => {
      try {
        const ts = new Date().getTime();
        const res = await fetch(`/api/project/metadata?t=${ts}`, { cache: 'no-store' });
        
        if (res.status === 401) {
          window.location.reload();
          return;
        }
        
        if (res.ok) {
          errorCount = 0; // reset on success
          const data = await res.json();
          // Use the current store state to check if project path changed
          const currentMeta = useDesignerStore.getState().metadata;
          if (currentMeta && data.project_path && data.project_path !== currentMeta.project_path) {
            console.log('Project changed detected in backend, reloading workspace...');
            fetchProject();
          }
        } else {
          errorCount++;
        }
      } catch (e) {
        // Track network errors (e.g. server stopped)
        errorCount++;
      }
      
      // If we fail 3 times consecutively (9 seconds), forcefully kick out
      if (errorCount >= 3) {
        console.warn('Lost connection to backend or sharing stopped. Reloading to lock workspace.');
        window.location.reload();
      }
    }, 3000);
    return () => clearInterval(intervalId);
  }, [fetchProject]);

  // Synchronize theme with document class list for Tailwind
  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDarkMode]);

  // Debounced auto-save effect
  useEffect(() => {
    if (!hasUnsavedChanges) return;

    const timer = setTimeout(() => {
      saveProject(true); // Call auto-save
    }, 3000); // 3-second debounce

    return () => clearTimeout(timer);
  }, [hasUnsavedChanges, saveProject]);

  const handleDragStart = (event: React.DragEvent, nodeType: string, elementType?: string) => {
    event.dataTransfer.setData('application/reactflow-type', nodeType);
    if (elementType) {
      event.dataTransfer.setData('application/reactflow-elementtype', elementType);
    }
    event.dataTransfer.effectAllowed = 'move';
  };

  return (
    <div className="w-screen h-screen flex flex-col bg-slate-50 dark:bg-background text-slate-800 dark:text-text select-none">
      {/* Main Header */}
      <header className="h-16 bg-white dark:bg-slate-950 border-b border-slate-200 dark:border-border flex items-center justify-between px-6 shrink-0 z-20">
        <div className="flex items-center gap-3">
          <div className="bg-primary-500/10 p-2 rounded-lg border border-primary-500/25">
            <ShieldAlert className="w-5 h-5 text-primary-500" />
          </div>
          <div>
            <h1 className="text-sm font-extrabold tracking-wide uppercase font-sans">
              ThreatPilot Designer
            </h1>
            <p className="text-[10px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">
              Project: {projectName}
            </p>
          </div>
        </div>

        {/* View switcher tabs */}
        <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-border p-1 rounded-lg">
          <button
            onClick={() => setCurrentView('canvas')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition ${currentView === 'canvas' ? 'bg-primary-600 text-white shadow-sm' : 'text-slate-650 dark:text-slate-350 hover:bg-slate-200 dark:hover:bg-slate-800'}`}
          >
            Architecture Canvas
          </button>
          <button
            onClick={() => setCurrentView('ledger')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition ${currentView === 'ledger' ? 'bg-primary-600 text-white shadow-sm' : 'text-slate-650 dark:text-slate-350 hover:bg-slate-250 dark:hover:bg-slate-800'}`}
          >
            Security Ledger
          </button>
          <button
            onClick={() => setCurrentView('reports')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition ${currentView === 'reports' ? 'bg-primary-600 text-white shadow-sm' : 'text-slate-650 dark:text-slate-350 hover:bg-slate-250 dark:hover:bg-slate-800'}`}
          >
            Reports & Exports
          </button>
        </div>

        {/* Save & Theme Controls */}
        <div className="flex items-center gap-3">
          {saveError && (
            <span className="text-xs text-red-400 font-semibold max-w-[200px] truncate">
              {saveError}
            </span>
          )}

          <div className="flex items-center gap-2">
            {isSaving ? (
              <span className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1.5 font-medium">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-primary-500" />
                Saving to project...
              </span>
            ) : hasUnsavedChanges ? (
              <span className="text-xs text-amber-500 dark:text-amber-400 font-medium">
                Unsaved edits pending
              </span>
            ) : (
              <span className="text-xs text-emerald-500 dark:text-emerald-400 font-medium">
                All changes synced
              </span>
            )}
          </div>

          <button
            onClick={toggleTheme}
            className="p-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-border rounded-lg text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-text transition mr-1"
            title={isDarkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}
          >
            {isDarkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>

          <button
            onClick={() => { fetchPromptConfig(); setIsBusinessContextModalOpen(true); }}
            className="flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-border rounded-lg text-slate-700 dark:text-slate-300 text-xs font-semibold transition"
          >
            <Briefcase className="w-3.5 h-3.5" />
            Project Context
          </button>

          <button
            onClick={() => { fetchAIConfig(); setIsConfigModalOpen(true); }}
            className="flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-border rounded-lg text-slate-700 dark:text-slate-300 text-xs font-semibold transition"
          >
            <Settings className="w-3.5 h-3.5" />
            Configure AI
          </button>

          <button
            onClick={() => setIsAnalysisModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg shadow-md transition disabled:opacity-50"
            disabled={analysisState.status === 'running'}
          >
            <Brain className="w-3.5 h-3.5" />
            Run AI Analysis
          </button>

          <button
            onClick={handleGenerateNarrative}
            className="flex items-center gap-1.5 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg shadow-md transition disabled:opacity-50"
            disabled={isGeneratingNarrative}
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            Generate Narrative
          </button>

          <button
            onClick={toggleRiskInCanvas}
            className="flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-border rounded-lg text-slate-700 dark:text-slate-300 text-xs font-semibold transition"
            title={showRiskInCanvas ? "Hide risk badges on components" : "Show risk badges on components"}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            {showRiskInCanvas ? 'Hide Risks' : 'Show Risks'}
          </button>

          <button
            onClick={() => saveProject(false)}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-primary-600 hover:bg-primary-500 text-white text-xs font-semibold rounded-lg shadow-md transition disabled:opacity-50"
            disabled={isSaving}
          >
            <Save className="w-3.5 h-3.5" />
            Save Diagram
          </button>
        </div>
      </header>

      {/* Global AI Progress Indicator */}
      {analysisState.status === 'running' && (
        <div className="absolute top-20 left-1/2 transform -translate-x-1/2 z-50 bg-indigo-600 text-white px-5 py-2.5 rounded-full shadow-xl flex items-center gap-3 font-semibold text-xs border border-indigo-500/50 backdrop-blur-sm shadow-indigo-500/20">
          <RefreshCw className="w-4 h-4 animate-spin text-indigo-200" />
          <span className="flex-1 tracking-wide">
            {analysisState.total_segments > 0 
              ? `Analyzing Segment ${analysisState.current_segment} of ${analysisState.total_segments}...` 
              : 'Analyzing Threat Model...'}
          </span>
        </div>
      )}

      {/* Main Panel Body */}
      {isLoading ? (
        <div className="flex-1 w-full flex items-center justify-center flex-col gap-3">
          <RefreshCw className="w-8 h-8 text-primary-500 animate-spin" />
          <p className="text-xs text-slate-400 font-mono">Loading ThreatPilot Project Model...</p>
        </div>
      ) : (
        <div className="flex-1 flex overflow-hidden">
          {currentView === 'canvas' && (
            <div className="flex-1 flex overflow-hidden">
              {/* Sidebar Left: Palette, Validation, Outputs */}
              <div className="w-80 border-r border-slate-200 dark:border-border bg-white dark:bg-card flex flex-col overflow-hidden shrink-0">
                {/* Component Palette */}
                <div className="p-4 border-b border-slate-200 dark:border-border shrink-0">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-1.5">
                    <Layers className="w-4 h-4 text-primary-500" />
                    Component Palette
                  </h3>
                  <p className="text-[10px] text-slate-500 dark:text-slate-400 leading-normal mb-3">
                    Drag and drop security elements directly onto the infinite canvas to configure your DFD structure.
                  </p>

                  <div className="grid grid-cols-2 gap-2">
                    <div
                      draggable
                      onDragStart={(e) => handleDragStart(e, 'componentNode', 'Process')}
                      className="px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold hover:border-emerald-500/40 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white cursor-grab transition select-none flex items-center gap-2"
                    >
                      <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                      Process
                    </div>
                    <div
                      draggable
                      onDragStart={(e) => handleDragStart(e, 'componentNode', 'Data Store')}
                      className="px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold hover:border-amber-500/40 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white cursor-grab transition select-none flex items-center gap-2"
                    >
                      <div className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                      Data Store
                    </div>
                    <div
                      draggable
                      onDragStart={(e) => handleDragStart(e, 'componentNode', 'Entity')}
                      className="px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold hover:border-blue-500/40 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white cursor-grab transition select-none flex items-center gap-2"
                    >
                      <div className="w-2.5 h-2.5 rounded-full bg-blue-500" />
                      Entity
                    </div>
                    <div
                      draggable
                      onDragStart={(e) => handleDragStart(e, 'boundaryNode')}
                      className="px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold hover:border-red-500/40 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white cursor-grab transition select-none flex items-center gap-2"
                    >
                      <div className="w-2.5 h-2.5 rounded-none border border-dashed border-red-500" />
                      Boundary
                    </div>
                  </div>
                </div>

                {/* Split Lower Sidebar: Validation & Export */}
                <div className="flex-1 flex flex-col divide-y divide-slate-200 dark:divide-border overflow-hidden">
                  <div className="flex-1 overflow-hidden">
                    <ValidationPanel />
                  </div>
                  <div className="flex-1 overflow-hidden">
                    <ExportOutputPanel />
                  </div>
                </div>
              </div>

              {/* Central Workspace: Interactive React Flow Canvas */}
              <div className="flex-1 h-full overflow-hidden">
                <Canvas />
              </div>

              {/* Sidebar Right: Context Properties */}
              <PropertiesPanel />
            </div>
          )}

          {currentView === 'ledger' && (
            <div className="flex-1 overflow-auto p-8 select-text bg-slate-50 dark:bg-background">
              <div className="max-w-[95%] mx-auto space-y-6">

                {/* Status indicator for mitigations review */}
                {mitigationsState.status === 'running' && (
                  <div className="bg-primary-500/10 border border-primary-500/25 p-4 rounded-xl flex flex-col gap-2">
                    <span className="text-xs font-bold text-primary-600 dark:text-primary-400 flex items-center gap-2">
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      {mitigationsState.progress || 'Processing mitigations AI review...'}
                    </span>
                  </div>
                )}

                <div className="flex justify-between items-center bg-white dark:bg-slate-900 border border-slate-200 dark:border-border p-6 rounded-xl shadow-sm">
                  <div>
                    <h2 className="text-lg font-bold text-slate-950 dark:text-white flex items-center gap-2">
                      <ShieldAlert className="w-5 h-5 text-amber-500" />
                      {ledgerTab === 'threats'
                        ? 'Threats'
                        : ledgerTab === 'vulnerabilities'
                          ? 'Identified Vulnerabilities Register'
                          : ledgerTab === 'assessment'
                            ? 'Risk Assessment'
                            : 'Consolidated Security Controls & Requirements'}
                    </h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      {ledgerTab === 'threats'
                        ? 'Manage all active architectural threat vectors identified in DFD analysis.'
                        : ledgerTab === 'vulnerabilities'
                          ? 'Review CVE vulnerability disclosures and remediation plans mapped to elements.'
                          : ledgerTab === 'assessment'
                            ? 'Conduct formal risk assessment with CVSS vectors, impact ratings, and severity rankings.'
                            : 'Review deduplicated and consolidated security requirements for implementation.'}
                    </p>
                  </div>

                  <div className="flex items-center gap-3">
                    {ledgerTab === 'mitigations' && (
                      <div className="flex items-center gap-2">
                        <button
                          onClick={triggerMitigationsReview}
                          disabled={mitigationsState.status === 'running'}
                          className="flex items-center gap-1.5 px-3 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg shadow-md transition disabled:opacity-50"
                        >
                          <Brain className="w-3.5 h-3.5" />
                          Run Mitigations AI Review
                        </button>
                        <button
                          onClick={() => window.open('/api/export/checklist_excel')}
                          className="flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-950 dark:hover:bg-slate-800 border border-slate-200 dark:border-border text-slate-700 dark:text-slate-300 text-xs font-semibold rounded-lg shadow-md transition"
                        >
                          <Download className="w-3.5 h-3.5" />
                          Export to Excel
                        </button>
                      </div>
                    )}
                    {getSelectedCount() > 0 && (
                      <button
                        onClick={handleBulkDelete}
                        className="flex items-center gap-1.5 px-3 py-2 bg-red-50 hover:bg-red-100 text-red-600 dark:bg-red-500/10 dark:hover:bg-red-500/20 dark:text-red-400 border border-red-200 dark:border-red-500/20 text-xs font-semibold rounded-lg shadow-sm transition mr-2"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        Delete Selected ({getSelectedCount()})
                      </button>
                    )}

                    {ledgerTab === 'threats' && (
                      <button
                        onClick={() => setIsAddingThreat(true)}
                        className="flex items-center gap-1.5 px-3 py-2 bg-primary-600 hover:bg-primary-500 text-white text-xs font-semibold rounded-lg shadow-md transition mr-2"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        Add Threat
                      </button>
                    )}
                    {ledgerTab === 'vulnerabilities' && (
                      <button
                        onClick={() => setIsAddingVuln(true)}
                        className="flex items-center gap-1.5 px-3 py-2 bg-primary-600 hover:bg-primary-500 text-white text-xs font-semibold rounded-lg shadow-md transition mr-2"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        Add Vulnerability
                      </button>
                    )}
                    {ledgerTab === 'assessment' && (
                      <button
                        onClick={() => setIsAddingRisk(true)}
                        className="flex items-center gap-1.5 px-3 py-2 bg-primary-600 hover:bg-primary-500 text-white text-xs font-semibold rounded-lg shadow-md transition mr-2"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        Add Risk
                      </button>
                    )}
                    {ledgerTab === 'mitigations' && (
                      <div className="flex gap-2 mr-2">
                        <button
                          onClick={() => setIsAddingMitigation(true)}
                          className="flex items-center gap-1.5 px-3 py-2 bg-primary-600 hover:bg-primary-500 text-white text-xs font-semibold rounded-lg shadow-md transition"
                        >
                          <Plus className="w-3.5 h-3.5" />
                          Add Mitigation
                        </button>
                        <button
                          onClick={() => setIsJiraSettingsOpen(true)}
                          className="flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-border text-xs font-semibold rounded-lg shadow-sm transition"
                        >
                          <svg className="w-3.5 h-3.5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                          Jira Settings
                        </button>
                        <button
                          onClick={() => handleSyncJira()}
                          disabled={isSyncingAll}
                          className="flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-border text-xs font-semibold rounded-lg shadow-sm transition disabled:opacity-50"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${isSyncingAll ? 'animate-spin' : ''}`} />
                          Sync All to Jira
                        </button>
                      </div>
                    )}

                    <div className="relative w-64">
                      <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
                      <input
                        type="text"
                        placeholder="Search ledger..."
                        value={ledgerSearch}
                        onChange={(e) => setLedgerSearch(e.target.value)}
                        className="w-full pl-9 pr-4 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold focus:outline-none focus:border-primary-500 text-slate-800 dark:text-white"
                      />
                    </div>
                  </div>
                </div>

                {/* Sub tabs switcher */}
                <div className="flex border-b border-slate-200 dark:border-border">
                  <button
                    onClick={() => setLedgerTab('threats')}
                    className={`px-4 py-2.5 text-xs font-bold border-b-2 transition ${ledgerTab === 'threats' ? 'border-primary-600 text-primary-600 dark:text-primary-400' : 'border-transparent text-slate-500 hover:text-slate-700'}`}
                  >
                    Threats ({uniqueThreats.length})
                  </button>
                  <button
                    onClick={() => setLedgerTab('vulnerabilities')}
                    className={`px-4 py-2.5 text-xs font-bold border-b-2 transition ${ledgerTab === 'vulnerabilities' ? 'border-primary-600 text-primary-600 dark:text-primary-400' : 'border-transparent text-slate-500 hover:text-slate-700'}`}
                  >
                    Vulnerabilities ({uniqueVulns.length})
                  </button>
                  <button
                    onClick={() => setLedgerTab('assessment')}
                    className={`px-4 py-2.5 text-xs font-bold border-b-2 transition ${ledgerTab === 'assessment' ? 'border-primary-600 text-primary-600 dark:text-primary-400' : 'border-transparent text-slate-500 hover:text-slate-700'}`}
                  >
                    Risk Assessment
                  </button>
                  <button
                    onClick={() => setLedgerTab('mitigations')}
                    className={`px-4 py-2.5 text-xs font-bold border-b-2 transition ${ledgerTab === 'mitigations' ? 'border-primary-600 text-primary-600 dark:text-primary-400' : 'border-transparent text-slate-500 hover:text-slate-700'}`}
                  >
                    Mitigation Requirements ({mitigationRequirements.length})
                  </button>
                </div>

                {ledgerTab === 'threats' ? (
                  <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-sm overflow-hidden">
                    <table className="w-full border-collapse text-left">
                      <thead>
                        <tr className="bg-slate-50 dark:bg-slate-950 text-[10px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200 dark:border-border select-none">
                          <th className="px-4 py-4 w-10">
                            <input
                              type="checkbox"
                              checked={uniqueThreats.length > 0 && selectedThreatIds.size === uniqueThreats.length}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedThreatIds(new Set(uniqueThreats.map(t => t.threat_id)));
                                } else {
                                  setSelectedThreatIds(new Set());
                                }
                              }}
                              className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500"
                            />
                          </th>
                          <th className="px-4 py-4 w-12 text-center">Sl</th>
                          <th className="px-6 py-4">Threat</th>
                          <th className="px-6 py-4">Category</th>
                          <th className="px-6 py-4">Affected Components</th>
                          <th className="px-6 py-4">Mitigation</th>
                          <th className="px-6 py-4">CVSS / Risk</th>
                          <th className="px-6 py-4 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-border text-xs">
                        {uniqueThreats.filter(t => {
                          const search = ledgerSearch.toLowerCase();
                          return (
                            (t.title || '').toLowerCase().includes(search) ||
                            (t.description || '').toLowerCase().includes(search) ||
                            (t.category || '').toLowerCase().includes(search) ||
                            (t.affected_components || '').toLowerCase().includes(search)
                          );
                        }).length === 0 ? (
                          <tr>
                            <td colSpan={8} className="text-center py-12 text-slate-400 italic">
                              No threats found matching search criteria.
                            </td>
                          </tr>
                        ) : (
                          uniqueThreats.filter(t => {
                            const search = ledgerSearch.toLowerCase();
                            return (
                              (t.title || '').toLowerCase().includes(search) ||
                              (t.description || '').toLowerCase().includes(search) ||
                              (t.category || '').toLowerCase().includes(search) ||
                              (t.affected_components || '').toLowerCase().includes(search)
                            );
                          }).map((t, idx) => {
                            return (
                              <tr key={t.threat_id} className="hover:bg-slate-50/50 dark:hover:bg-slate-950/20">
                                <td className="px-4 py-4">
                                  <input
                                    type="checkbox"
                                    checked={selectedThreatIds.has(t.threat_id)}
                                    onChange={(e) => {
                                      const next = new Set(selectedThreatIds);
                                      if (e.target.checked) next.add(t.threat_id);
                                      else next.delete(t.threat_id);
                                      setSelectedThreatIds(next);
                                    }}
                                    className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500"
                                  />
                                </td>
                                <td className="px-4 py-4 text-center text-slate-400 font-mono">{idx + 1}</td>
                                <td className="px-6 py-4 max-w-xs">
                                  <div>
                                    <span className="font-bold text-slate-900 dark:text-text block">{t.title}</span>
                                    <span className="text-slate-500 dark:text-slate-400 mt-1 block leading-normal">{t.description}</span>
                                  </div>
                                </td>
                                <td className="px-6 py-4">
                                  <span className="px-2 py-0.5 bg-amber-500/10 text-amber-500 text-[10px] font-semibold uppercase tracking-wider rounded border border-amber-500/20">
                                    {t.category}
                                  </span>
                                </td>
                                <td className="px-6 py-4 text-slate-500 dark:text-slate-400 font-mono text-[11px]">
                                  {t.affected_components || 'Global'}
                                </td>
                                <td className="px-6 py-4 max-w-xs">
                                  <span className="italic leading-normal text-slate-655 dark:text-slate-355">{t.mitigation || 'No mitigation configured'}</span>
                                </td>
                                <td className="px-6 py-4">
                                  <div className="space-y-1">
                                    {t.cvss_score > 0 ? (
                                      <span className="font-bold text-red-500 block">CVSS: {t.cvss_score}</span>
                                    ) : (
                                      <span className="text-slate-400 block font-mono">N/A</span>
                                    )}
                                    {t.cvss_vector && (
                                      <span className="text-[9px] text-slate-400 dark:text-slate-500 font-mono block select-all break-all max-w-[120px]" title="CVSS Vector String">
                                        {t.cvss_vector}
                                      </span>
                                    )}
                                    {t.is_accepted_risk ? (
                                      <span className="px-1.5 py-0.5 bg-emerald-500/10 text-emerald-500 text-[9px] font-bold uppercase rounded border border-emerald-500/20">Accepted</span>
                                    ) : (
                                      <span className="px-1.5 py-0.5 bg-red-500/10 text-red-500 text-[9px] font-bold uppercase rounded border border-red-500/20">Open</span>
                                    )}
                                  </div>
                                </td>
                                <td className="px-6 py-4 text-right">
                                  <div className="flex justify-end gap-2">
                                    {t.reasoning ? (
                                      <div className="flex gap-1">
                                        <button
                                          onClick={() => {
                                            setReasoningModalTitle(`Threat XAI: ${t.title}`);
                                            setReasoningModalContent(t.reasoning || '');
                                          }}
                                          className="flex items-center gap-1 px-2.5 py-1.5 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20 text-[10px] font-bold rounded-lg border border-emerald-500/20 transition"
                                          title="Show XAI Technical Reasoning"
                                        >
                                          <Sparkles className="w-3 h-3" />
                                          Show xAI Reasoning
                                        </button>
                                        <button
                                          onClick={() => runThreatAIAnalysis(t.threat_id)}
                                          disabled={generatingReasoningThreatId === t.threat_id}
                                          className="flex items-center gap-1 px-2 py-1.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 text-[10px] font-bold rounded-lg border border-slate-200 dark:border-border transition disabled:opacity-50"
                                          title="Regenerate XAI Reasoning"
                                        >
                                          <RefreshCw className={`w-3 h-3 ${generatingReasoningThreatId === t.threat_id ? 'animate-spin' : ''}`} />
                                        </button>
                                      </div>
                                    ) : (
                                      <button
                                        onClick={() => runThreatAIAnalysis(t.threat_id)}
                                        disabled={generatingReasoningThreatId === t.threat_id}
                                        className="flex items-center gap-1 px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 text-[10px] font-bold rounded-lg border border-slate-200 dark:border-border transition disabled:opacity-50"
                                        title="Run AI Analysis"
                                      >
                                        <Sparkles className={`w-3 h-3 ${generatingReasoningThreatId === t.threat_id ? 'animate-pulse text-emerald-500' : ''}`} />
                                        {generatingReasoningThreatId === t.threat_id ? 'Analyzing...' : 'Run AI Analysis'}
                                      </button>
                                    )}
                                    <button
                                      onClick={() => setEditingThreat({ ...t })}
                                      className="p-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-border text-slate-655 dark:text-slate-355 rounded-lg transition"
                                      title="Edit Threat Metrics"
                                    >
                                      <Edit className="w-3.5 h-3.5" />
                                    </button>
                                    <button
                                      onClick={() => { if (confirm('Delete this threat?')) deleteThreat(t.threat_id); }}
                                      className="p-1.5 bg-slate-100 hover:bg-red-50 dark:bg-slate-900 dark:hover:bg-red-500/10 border border-slate-200 dark:border-border text-slate-600 dark:text-slate-455 hover:text-red-500 rounded-lg transition"
                                    >
                                      <Trash2 className="w-3.5 h-3.5" />
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>
                ) : ledgerTab === 'vulnerabilities' ? (
                  <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-sm overflow-hidden">
                    <table className="w-full border-collapse text-left">
                      <thead>
                        <tr className="bg-slate-50 dark:bg-slate-950 text-[10px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200 dark:border-border select-none">
                          <th className="px-4 py-4 w-10">
                            <input
                              type="checkbox"
                              checked={uniqueVulns.length > 0 && selectedVulnIds.size === uniqueVulns.length}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedVulnIds(new Set(uniqueVulns.map(v => v.vulnerability_id)));
                                } else {
                                  setSelectedVulnIds(new Set());
                                }
                              }}
                              className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500"
                            />
                          </th>
                          <th className="px-4 py-4 w-12 text-center">Sl</th>
                          <th className="px-6 py-4">Vulnerability Title & Description</th>
                          <th className="px-6 py-4">Mitigation Description</th>
                          <th className="px-6 py-4">Status</th>
                          <th className="px-6 py-4 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-border text-xs">
                        {uniqueVulns.filter(v => {
                          const search = ledgerSearch.toLowerCase();
                          return (
                            (v.title || '').toLowerCase().includes(search) ||
                            (v.description || '').toLowerCase().includes(search) ||
                            (v.mitigation || '').toLowerCase().includes(search)
                          );
                        }).length === 0 ? (
                          <tr>
                            <td colSpan={6} className="text-center py-12 text-slate-400 italic">
                              No vulnerabilities found matching search criteria.
                            </td>
                          </tr>
                        ) : (
                          uniqueVulns.filter(v => {
                            const search = ledgerSearch.toLowerCase();
                            return (
                              (v.title || '').toLowerCase().includes(search) ||
                              (v.description || '').toLowerCase().includes(search) ||
                              (v.mitigation || '').toLowerCase().includes(search)
                            );
                          }).map((v, idx) => {
                            return (
                              <tr key={v.vulnerability_id} className="hover:bg-slate-50/50 dark:hover:bg-slate-950/20">
                                <td className="px-4 py-4">
                                  <input
                                    type="checkbox"
                                    checked={selectedVulnIds.has(v.vulnerability_id)}
                                    onChange={(e) => {
                                      const next = new Set(selectedVulnIds);
                                      if (e.target.checked) next.add(v.vulnerability_id);
                                      else next.delete(v.vulnerability_id);
                                      setSelectedVulnIds(next);
                                    }}
                                    className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500"
                                  />
                                </td>
                                <td className="px-4 py-4 text-center text-slate-400 font-mono">{idx + 1}</td>
                                <td className="px-6 py-4 max-w-md">
                                  <div>
                                    <span className="font-bold text-slate-900 dark:text-text block">{v.title}</span>
                                    <span className="text-slate-500 dark:text-slate-400 mt-1 block leading-normal">{v.description}</span>
                                    {v.reasoning && (
                                      <div className="mt-2 bg-slate-100/50 dark:bg-slate-950/40 p-2.5 rounded text-[10px] leading-relaxed max-h-36 overflow-y-auto select-text font-normal">
                                        <span className="text-[8px] font-bold uppercase tracking-wider text-primary-500 block mb-1">XAI Reasoning</span>
                                        {renderMarkdown(v.reasoning)}
                                      </div>
                                    )}
                                  </div>
                                </td>
                                <td className="px-6 py-4 max-w-sm">
                                  {(() => {
                                    const parentThreat = uniqueThreats.find(t => t.vulnerability_ids?.includes(v.vulnerability_id));
                                    const mitigationText = v.mitigation || parentThreat?.mitigation || 'No mitigation configured';
                                    return (
                                      <span className="italic leading-normal text-slate-655 dark:text-slate-355">{mitigationText}</span>
                                    );
                                  })()}
                                </td>
                                <td className="px-6 py-4">
                                  <span className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded border ${v.status === 'Remediated' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 'bg-red-500/10 text-red-500 border-red-500/20'}`}>
                                    {v.status || 'Open'}
                                  </span>
                                </td>
                                <td className="px-6 py-4 text-right">
                                  <div className="flex justify-end gap-2">
                                    {v.reasoning ? (
                                      <div className="flex gap-1">
                                        <button
                                          onClick={() => {
                                            setReasoningModalTitle(`Vulnerability XAI: ${v.title}`);
                                            setReasoningModalContent(v.reasoning || '');
                                          }}
                                          className="flex items-center gap-1 px-2.5 py-1.5 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20 text-[10px] font-bold rounded-lg border border-emerald-500/20 transition"
                                          title="Show XAI Technical Reasoning"
                                        >
                                          <Sparkles className="w-3 h-3" />
                                          Show xAI Reasoning
                                        </button>
                                        <button
                                          onClick={() => runVulnerabilityAIAnalysis(v.vulnerability_id)}
                                          disabled={generatingReasoningVulnId === v.vulnerability_id}
                                          className="flex items-center gap-1 px-2 py-1.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 text-[10px] font-bold rounded-lg border border-slate-200 dark:border-border transition disabled:opacity-50"
                                          title="Regenerate XAI Reasoning"
                                        >
                                          <RefreshCw className={`w-3 h-3 ${generatingReasoningVulnId === v.vulnerability_id ? 'animate-spin' : ''}`} />
                                        </button>
                                      </div>
                                    ) : (
                                      <button
                                        onClick={() => runVulnerabilityAIAnalysis(v.vulnerability_id)}
                                        disabled={generatingReasoningVulnId === v.vulnerability_id}
                                        className="flex items-center gap-1 px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 text-[10px] font-bold rounded-lg border border-slate-200 dark:border-border transition disabled:opacity-50"
                                        title="Run AI Analysis"
                                      >
                                        <Sparkles className={`w-3 h-3 ${generatingReasoningVulnId === v.vulnerability_id ? 'animate-pulse text-emerald-500' : ''}`} />
                                        {generatingReasoningVulnId === v.vulnerability_id ? 'Analyzing...' : 'Run AI Analysis'}
                                      </button>
                                    )}
                                    <button
                                      onClick={() => setEditingVuln({ ...v })}
                                      className="p-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-border text-slate-655 dark:text-slate-355 rounded-lg transition"
                                      title="Edit Vulnerability"
                                    >
                                      <Edit className="w-3.5 h-3.5" />
                                    </button>
                                    <button
                                      onClick={() => { if (confirm('Delete this vulnerability?')) deleteVulnerability(v.vulnerability_id); }}
                                      className="p-1.5 bg-slate-100 hover:bg-red-50 dark:bg-slate-900 dark:hover:bg-red-500/10 border border-slate-200 dark:border-border text-slate-600 dark:text-slate-455 hover:text-red-500 rounded-lg transition"
                                    >
                                      <Trash2 className="w-3.5 h-3.5" />
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>
                ) : ledgerTab === 'assessment' ? (
                  <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-sm overflow-x-auto">
                    <table className="w-full border-collapse text-left min-w-[1200px]">
                      <thead>
                        <tr className="bg-slate-50 dark:bg-slate-950 text-[10px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200 dark:border-border select-none">
                          <th className="px-4 py-4 w-10">
                            <input
                              type="checkbox"
                              checked={uniqueThreats.length > 0 && selectedRiskIds.size === uniqueThreats.length}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedRiskIds(new Set(uniqueThreats.map(t => t.threat_id)));
                                } else {
                                  setSelectedRiskIds(new Set());
                                }
                              }}
                              className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500"
                            />
                          </th>
                          <th className="px-4 py-4 w-12 text-center">Sl</th>
                          <th className="px-4 py-4">Elements</th>
                          <th className="px-4 py-4">Assets</th>
                          <th className="px-4 py-4">Threats</th>
                          <th className="px-4 py-4">Vulnerabilities</th>
                          <th className="px-4 py-4 max-w-xs">Risk Description</th>
                          <th className="px-4 py-4">Impact</th>
                          <th className="px-4 py-4">CVSS Vector</th>
                          <th className="px-4 py-4">Likelihood</th>
                          <th className="px-4 py-4">Severity</th>
                          <th className="px-4 py-4 max-w-xs">Mitigations</th>
                          <th className="px-4 py-4 text-center">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-border text-xs">
                        {uniqueThreats.filter(t => {
                          const search = ledgerSearch.toLowerCase();
                          return (
                            (t.title || '').toLowerCase().includes(search) ||
                            (t.description || '').toLowerCase().includes(search) ||
                            (t.category || '').toLowerCase().includes(search) ||
                            (t.affected_components || '').toLowerCase().includes(search)
                          );
                        }).length === 0 ? (
                          <tr>
                            <td colSpan={13} className="text-center py-12 text-slate-400 italic">
                              No assessment records found.
                            </td>
                          </tr>
                        ) : (
                          uniqueThreats.filter(t => {
                            const search = ledgerSearch.toLowerCase();
                            return (
                              (t.title || '').toLowerCase().includes(search) ||
                              (t.description || '').toLowerCase().includes(search) ||
                              (t.category || '').toLowerCase().includes(search) ||
                              (t.affected_components || '').toLowerCase().includes(search)
                            );
                          }).map((t, idx) => {
                            const genericTypes = ['data flow', 'informational', 'physical', 'process', 'data store', 'external entity', 'n/a', ''];
                            let assetNames = (t as any).affected_asset_type || '';
                            if (!assetNames || genericTypes.includes(assetNames.toLowerCase())) {
                              // Resolve from affected_components: match component names
                              const compHints = (t.affected_components || '').split(',').map((s: string) => s.trim()).filter(Boolean);
                              let resolved = '';
                              for (const hint of compHints) {
                                const compMatch = nodes.find(n => n.type === 'componentNode' && n.data?.name === hint);
                                if (compMatch) { resolved = compMatch.data?.name || hint; break; }
                              }
                              if (!resolved) {
                                // Fuzzy: search description for any component name
                                const haystack = `${t.title} ${t.description}`.toLowerCase();
                                for (const n of nodes.filter(n => n.type === 'componentNode')) {
                                  if (n.data?.name && haystack.includes(n.data.name.toLowerCase())) {
                                    resolved = n.data.name; break;
                                  }
                                }
                              }
                              assetNames = resolved || t.affected_components || 'N/A';
                            }
                            const matchingVulns = (t.vulnerability_ids || []).map(vid => {
                              return uniqueVulns.find(v => v.vulnerability_id === vid)?.title || vid;
                            }).join(', ');

                            return (
                              <tr key={t.threat_id} className="hover:bg-slate-50/50 dark:hover:bg-slate-950/20">
                                <td className="px-4 py-4">
                                  <input
                                    type="checkbox"
                                    checked={selectedRiskIds.has(t.threat_id)}
                                    onChange={(e) => {
                                      const next = new Set(selectedRiskIds);
                                      if (e.target.checked) next.add(t.threat_id);
                                      else next.delete(t.threat_id);
                                      setSelectedRiskIds(next);
                                    }}
                                    className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500"
                                  />
                                </td>
                                <td className="px-4 py-4 text-center text-slate-400 font-mono">{idx + 1}</td>
                                <td className="px-4 py-4 font-semibold text-slate-800 dark:text-text">{t.affected_components || 'Global'}</td>
                                <td className="px-4 py-4 font-mono text-[10px] text-slate-500 dark:text-slate-450">{assetNames}</td>
                                <td className="px-4 py-4 font-bold text-slate-900 dark:text-white">{t.title}</td>
                                <td className="px-4 py-4 text-slate-500">{matchingVulns || 'None'}</td>
                                <td className="px-4 py-4 max-w-xs leading-normal text-slate-500 dark:text-slate-400">{t.description}</td>
                                <td className="px-4 py-4">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${t.impact === 'High' ? 'bg-red-500/10 text-red-500 border-red-500/20' : t.impact === 'Medium' ? 'bg-amber-500/10 text-amber-500 border-amber-500/20' : 'bg-blue-500/10 text-blue-500 border-blue-500/20'}`}>
                                    {t.impact || 'Medium'}
                                  </span>
                                </td>
                                <td className="px-4 py-4 font-mono text-[10px] text-slate-400 select-all break-all max-w-[150px]">{t.cvss_vector || 'N/A'}</td>
                                <td className="px-4 py-4 font-mono text-center">{t.likelihood || 3}</td>
                                <td className="px-4 py-4 font-bold text-red-500">{t.cvss_score || '0.0'}</td>
                                <td className="px-4 py-4 max-w-xs leading-normal italic text-slate-500">{t.mitigation || 'No mitigation configured'}</td>
                                <td className="px-4 py-4 text-center">
                                  <div className="flex justify-center gap-1.5">
                                    {t.reasoning ? (
                                      <div className="flex gap-1">
                                        <button
                                          onClick={() => {
                                            setReasoningModalTitle(`Threat XAI: ${t.title}`);
                                            setReasoningModalContent(t.reasoning || '');
                                          }}
                                          className="flex items-center gap-1 px-2 py-1 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20 text-[9px] font-bold rounded border border-emerald-500/20 transition"
                                          title="Show XAI Technical Reasoning"
                                        >
                                          <Sparkles className="w-2.5 h-2.5" />
                                          Show xAI
                                        </button>
                                        <button
                                          onClick={() => runThreatAIAnalysis(t.threat_id)}
                                          disabled={generatingReasoningThreatId === t.threat_id}
                                          className="flex items-center gap-1 px-1.5 py-1 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 text-[9px] font-bold rounded border border-slate-200 dark:border-border transition disabled:opacity-50"
                                          title="Regenerate XAI Reasoning"
                                        >
                                          <RefreshCw className={`w-2.5 h-2.5 ${generatingReasoningThreatId === t.threat_id ? 'animate-spin' : ''}`} />
                                        </button>
                                      </div>
                                    ) : (
                                      <button
                                        onClick={() => runThreatAIAnalysis(t.threat_id)}
                                        disabled={generatingReasoningThreatId === t.threat_id}
                                        className="flex items-center gap-1 px-2 py-1 bg-slate-105 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 text-[9px] font-bold rounded border border-slate-200 dark:border-border transition disabled:opacity-50"
                                        title="Run AI Analysis"
                                      >
                                        <Sparkles className={`w-2.5 h-2.5 ${generatingReasoningThreatId === t.threat_id ? 'animate-pulse text-emerald-500' : ''}`} />
                                        {generatingReasoningThreatId === t.threat_id ? 'Analyzing...' : 'Run AI'}
                                      </button>
                                    )}
                                    <button
                                      onClick={() => setEditingThreat({ ...t })}
                                      className="p-1 bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-border text-slate-655 dark:text-slate-355 rounded transition"
                                      title="Edit Risk Metrics"
                                    >
                                      <Edit className="w-3 h-3" />
                                    </button>
                                    <button
                                      onClick={() => { if (confirm('Delete this record?')) deleteThreat(t.threat_id); }}
                                      className="p-1 bg-slate-100 hover:bg-red-50 dark:bg-slate-900 dark:hover:bg-red-500/10 border border-slate-200 dark:border-border text-slate-600 dark:text-slate-455 hover:text-red-500 rounded transition"
                                    >
                                      <Trash2 className="w-3 h-3" />
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-sm overflow-hidden">
                    <table className="w-full border-collapse text-left">
                      <thead>
                        <tr className="bg-slate-50 dark:bg-slate-950 text-[10px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200 dark:border-border select-none">
                          <th className="px-4 py-4 w-10">
                            <input
                              type="checkbox"
                              checked={mitigationRequirements.length > 0 && selectedMitIds.size === mitigationRequirements.length}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedMitIds(new Set(mitigationRequirements.map(m => m.req_id)));
                                } else {
                                  setSelectedMitIds(new Set());
                                }
                              }}
                              className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500"
                            />
                          </th>
                          <th className="px-4 py-4 w-12 text-center">Sl</th>
                          <th className="px-6 py-4">ID / Control Title</th>
                          <th className="px-6 py-4">Security Requirement (Mitigation)</th>
                          <th className="px-6 py-4">Affected Components</th>
                          <th className="px-6 py-4">Validation Test Case</th>
                          <th className="px-6 py-4 text-center w-24">Jira</th>
                          <th className="px-6 py-4 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-border text-xs">
                        {mitigationRequirements.filter(r => {
                          const search = ledgerSearch.toLowerCase();
                          return (
                            r.title.toLowerCase().includes(search) ||
                            r.mitigation.toLowerCase().includes(search) ||
                            r.affected_components.toLowerCase().includes(search) ||
                            r.test_case.toLowerCase().includes(search)
                          );
                        }).length === 0 ? (
                          <tr>
                            <td colSpan={7} className="text-center py-12 text-slate-400 italic">
                              No mitigation requirements found. Click "Run Mitigations AI Review" to generate controls.
                            </td>
                          </tr>
                        ) : (
                          mitigationRequirements.filter(r => {
                            const search = ledgerSearch.toLowerCase();
                            return (
                              r.title.toLowerCase().includes(search) ||
                              r.mitigation.toLowerCase().includes(search) ||
                              r.affected_components.toLowerCase().includes(search) ||
                              r.test_case.toLowerCase().includes(search)
                            );
                          }).map((r, idx) => {
                            const isEditing = editingMitId === r.req_id;

                            return (
                              <tr key={r.req_id} className="hover:bg-slate-50/50 dark:hover:bg-slate-950/20">
                                <td className="px-4 py-4">
                                  <input
                                    type="checkbox"
                                    checked={selectedMitIds.has(r.req_id)}
                                    onChange={(e) => {
                                      const next = new Set(selectedMitIds);
                                      if (e.target.checked) next.add(r.req_id);
                                      else next.delete(r.req_id);
                                      setSelectedMitIds(next);
                                    }}
                                    className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500"
                                  />
                                </td>
                                <td className="px-4 py-4 text-center text-slate-400 font-mono">{idx + 1}</td>
                                <td className="px-6 py-4">
                                  <span className="font-mono text-[10px] text-slate-400 block">{r.req_id}</span>
                                  {isEditing ? (
                                    <input
                                      type="text"
                                      value={r.title}
                                      onChange={(e) => updateMitigationRequirement(r.req_id, { title: e.target.value })}
                                      className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-xs rounded p-1 text-slate-800 dark:text-white mt-1"
                                    />
                                  ) : (
                                    <span className="font-bold text-slate-900 dark:text-text block mt-0.5">{r.title}</span>
                                  )}
                                </td>
                                <td className="px-6 py-4 max-w-xs">
                                  {isEditing ? (
                                    <div className="space-y-1.5">
                                      <textarea
                                        value={r.mitigation}
                                        onChange={(e) => updateMitigationRequirement(r.req_id, { mitigation: e.target.value })}
                                        className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-xs rounded p-1 text-slate-700 dark:text-slate-300 resize-none h-14"
                                      />
                                      <textarea
                                        value={r.short_description}
                                        onChange={(e) => updateMitigationRequirement(r.req_id, { short_description: e.target.value })}
                                        className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-xs rounded p-1 text-slate-700 dark:text-slate-300 resize-none h-10"
                                        placeholder="Short description"
                                      />
                                    </div>
                                  ) : (
                                    <div>
                                      <p className="leading-normal text-slate-850 dark:text-slate-300">{r.mitigation}</p>
                                      {r.short_description && (
                                        <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-1">{r.short_description}</p>
                                      )}
                                    </div>
                                  )}
                                </td>
                                <td className="px-6 py-4 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                                  {isEditing ? (
                                    <input
                                      type="text"
                                      value={r.affected_components}
                                      onChange={(e) => updateMitigationRequirement(r.req_id, { affected_components: e.target.value })}
                                      className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-xs rounded p-1 text-slate-800 dark:text-white"
                                    />
                                  ) : (
                                    r.affected_components
                                  )}
                                </td>
                                <td className="px-6 py-4 max-w-xs text-slate-500 dark:text-slate-400">
                                  {isEditing ? (
                                    <textarea
                                      value={r.test_case}
                                      onChange={(e) => updateMitigationRequirement(r.req_id, { test_case: e.target.value })}
                                      className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-xs rounded p-1 text-slate-700 dark:text-slate-300 resize-none h-14"
                                    />
                                  ) : (
                                    r.test_case
                                  )}
                                </td>
                                <td className="px-6 py-4 text-center">
                                  {r.jira_issue_key ? (
                                    <a href={r.jira_issue_url} target="_blank" rel="noreferrer" className="text-[10px] font-bold text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 hover:underline">
                                      {r.jira_issue_key}
                                    </a>
                                  ) : (
                                    <button
                                      onClick={() => handleSyncJira(r.req_id)}
                                      disabled={syncingReqId === r.req_id || isSyncingAll}
                                      className="px-2 py-1 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 border border-slate-200 dark:border-border text-[10px] font-bold text-slate-600 dark:text-slate-400 rounded transition disabled:opacity-50"
                                    >
                                      {syncingReqId === r.req_id ? 'Syncing...' : 'Sync'}
                                    </button>
                                  )}
                                </td>
                                <td className="px-6 py-4 text-right">
                                  <div className="flex justify-end gap-2">
                                    {r.reasoning ? (
                                      <div className="flex gap-1">
                                        <button
                                          onClick={() => {
                                            setReasoningModalTitle(`Mitigation Control XAI: ${r.title}`);
                                            setReasoningModalContent(r.reasoning || '');
                                          }}
                                          className="flex items-center gap-1 px-2.5 py-1.5 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20 text-[10px] font-bold rounded-lg border border-emerald-500/20 transition"
                                          title="Show XAI Technical Reasoning"
                                        >
                                          <Sparkles className="w-3 h-3" />
                                          Show xAI Reasoning
                                        </button>
                                        <button
                                          onClick={() => runMitigationAIAnalysis(r.req_id)}
                                          disabled={generatingReasoningMitId === r.req_id}
                                          className="flex items-center gap-1 px-2 py-1.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 text-[10px] font-bold rounded-lg border border-slate-200 dark:border-border transition disabled:opacity-50"
                                          title="Regenerate XAI Reasoning"
                                        >
                                          <RefreshCw className={`w-3 h-3 ${generatingReasoningMitId === r.req_id ? 'animate-spin' : ''}`} />
                                        </button>
                                      </div>
                                    ) : (
                                      <button
                                        onClick={() => runMitigationAIAnalysis(r.req_id)}
                                        disabled={generatingReasoningMitId === r.req_id}
                                        className="flex items-center gap-1 px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 text-[10px] font-bold rounded-lg border border-slate-200 dark:border-border transition disabled:opacity-50"
                                        title="Run AI Analysis"
                                      >
                                        <Sparkles className={`w-3 h-3 ${generatingReasoningMitId === r.req_id ? 'animate-pulse text-emerald-500' : ''}`} />
                                        {generatingReasoningMitId === r.req_id ? 'Analyzing...' : 'Run AI Analysis'}
                                      </button>
                                    )}
                                    <button
                                      onClick={() => setEditingMitId(isEditing ? null : r.req_id)}
                                      className="p-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-border text-slate-655 dark:text-slate-355 rounded-lg transition"
                                    >
                                      <Edit className="w-3.5 h-3.5" />
                                    </button>
                                    <button
                                      onClick={() => { if (confirm('Delete this mitigation requirement?')) deleteMitigationRequirement(r.req_id); }}
                                      className="p-1.5 bg-slate-100 hover:bg-red-50 dark:bg-slate-900 dark:hover:bg-red-500/10 border border-slate-200 dark:border-border text-slate-600 dark:text-slate-450 hover:text-red-500 rounded-lg transition"
                                    >
                                      <Trash2 className="w-3.5 h-3.5" />
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {currentView === 'reports' && (
            <div className="flex-1 overflow-auto p-8 select-none bg-slate-50 dark:bg-background">
              <div className="max-w-4xl mx-auto space-y-6">
                <div>
                  <h2 className="text-lg font-bold text-slate-950 dark:text-white flex items-center gap-2">
                    <FileSpreadsheet className="w-5 h-5 text-primary-500" />
                    Reports & Exporters
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    Compile and download premium security audit reports, risk matrices, and compliance checklists.
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-6">
                  {/* Risk Excel */}
                  <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-sm p-6 flex flex-col gap-4">
                    <div className="flex gap-3">
                      <div className="bg-primary-500/10 p-2 rounded-lg border border-primary-500/20 text-primary-500">
                        <FileSpreadsheet className="w-6 h-6" />
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-slate-900 dark:text-white">Risk Assessment Matrix (Excel)</h3>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-normal">
                          Full threat register including likelihood, impact, CVSS scores, and status as a Microsoft Excel spreadsheet.
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => window.open('/api/export/excel')}
                      className="mt-auto py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-lg text-xs font-semibold shadow-md transition flex items-center justify-center gap-1.5"
                    >
                      <Download className="w-4 h-4" />
                      Download Excel Report
                    </button>
                  </div>

                  {/* Checklist Excel */}
                  <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-sm p-6 flex flex-col gap-4">
                    <div className="flex gap-3">
                      <div className="bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/20 text-emerald-500">
                        <FileSpreadsheet className="w-6 h-6" />
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-slate-900 dark:text-white">Mitigation Requirements (Excel)</h3>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-normal">
                          Excel sheet consolidating mitigations into discrete security controls, complete with test cases and verification plans.
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => window.open('/api/export/checklist_excel')}
                      className="mt-auto py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold shadow-md transition flex items-center justify-center gap-1.5"
                    >
                      <Download className="w-4 h-4" />
                      Download Excel Checklist
                    </button>
                  </div>

                  {/* HTML Report */}
                  <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-sm p-6 flex flex-col gap-4">
                    <div className="flex gap-3">
                      <div className="bg-blue-500/10 p-2 rounded-lg border border-blue-500/20 text-blue-500">
                        <FileCode className="w-6 h-6" />
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-slate-900 dark:text-white">Security Assessment Report (HTML)</h3>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-normal">
                          Full threat model details, diagram layout, and cataloged threats in a single, high-fidelity standalone HTML report.
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => window.open('/api/export/html')}
                      className="mt-auto py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-md transition flex items-center justify-center gap-1.5"
                    >
                      <Download className="w-4 h-4" />
                      Download HTML Report
                    </button>
                  </div>

                  {/* Checklist HTML */}
                  <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-sm p-6 flex flex-col gap-4">
                    <div className="flex gap-3">
                      <div className="bg-purple-500/10 p-2 rounded-lg border border-purple-500/20 text-purple-500">
                        <FileCode className="w-6 h-6" />
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-slate-900 dark:text-white">Mitigation Checklist (HTML)</h3>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-normal">
                          A standalone premium HTML checklist of security requirements with print layouts and status toggle widgets.
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => window.open('/api/export/checklist')}
                      className="mt-auto py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold shadow-md transition flex items-center justify-center gap-1.5"
                    >
                      <Download className="w-4 h-4" />
                      Download HTML Checklist
                    </button>
                  </div>
                </div>

                {/* Risk Matrix Component — 5x5 Likelihood vs Impact (CVSS-derived) */}
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-sm p-6 space-y-4 select-text">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                      <Shield className="w-4 h-4 text-primary-500" />
                      Strategic Risk Matrix
                    </h3>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 leading-normal">
                      Threats plotted by Likelihood (AI-identified) vs. Impact (CVSS-derived). Click any cell to inspect.
                    </p>
                  </div>

                  <div className="flex gap-4">
                    {/* Matrix Grid — rows: likelihood 5→1, cols: impact 1→5 */}
                    <div className="flex-1">
                      <div className="grid grid-cols-[110px_repeat(5,_1fr)] gap-1 text-center text-[11px]">
                        {/* Column headers: empty corner + impact 1-5 */}
                        <div />
                        {[1, 2, 3, 4, 5].map(col => (
                          <div key={col} className="font-bold py-1.5 text-slate-500 dark:text-slate-400">
                            {impactLabels[col]}
                          </div>
                        ))}

                        {/* Rows: Likelihood 5 (Certain) down to 1 (Rare) */}
                        {[5, 4, 3, 2, 1].map(likelihoodVal => (
                          <React.Fragment key={likelihoodVal}>
                            {/* Row Header */}
                            <div className="font-bold flex items-center justify-end pr-3 text-slate-500 dark:text-slate-400 text-[10px]">
                              {likelihoodLabels[likelihoodVal]}
                            </div>
                            {/* 5 impact columns */}
                            {[1, 2, 3, 4, 5].map(impactVal => {
                              const cellThreats = getThreatsForCell(likelihoodVal, impactVal);
                              const count = cellThreats.length;
                              const isSelected = selectedMatrixCell?.likelihood === likelihoodVal && selectedMatrixCell?.impactScore === impactVal;
                              return (
                                <button
                                  key={impactVal}
                                  onClick={() => {
                                    if (isSelected) {
                                      setSelectedMatrixCell(null);
                                    } else {
                                      setSelectedMatrixCell({ likelihood: likelihoodVal, impactScore: impactVal });
                                    }
                                  }}
                                  className={`h-14 flex flex-col items-center justify-center border rounded-lg transition-all cursor-pointer ${getCellColor(likelihoodVal, impactVal, count)}`}
                                >
                                  <span className="text-base font-extrabold">{count}</span>
                                </button>
                              );
                            })}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Filtered Threats List Container */}
                  {selectedMatrixCell && (
                    <div className="border-t border-slate-200 dark:border-border/30 pt-4 space-y-3 animate-in fade-in duration-150">
                      <div className="flex justify-between items-center">
                        <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                          Filtered Threats ({likelihoodLabels[selectedMatrixCell.likelihood]} × {impactLabels[selectedMatrixCell.impactScore]})
                          <span className="px-2 py-0.5 bg-primary-100 dark:bg-primary-950/40 text-primary-650 dark:text-primary-400 rounded-full text-[10px]">
                            {getThreatsForCell(selectedMatrixCell.likelihood, selectedMatrixCell.impactScore).length}
                          </span>
                        </span>
                        <button
                          onClick={() => setSelectedMatrixCell(null)}
                          className="text-[10px] font-semibold text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition"
                        >
                          Clear Filter
                        </button>
                      </div>

                      <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                        {getThreatsForCell(selectedMatrixCell.likelihood, selectedMatrixCell.impactScore).length === 0 ? (
                          <p className="text-xs text-slate-400 italic py-4 text-center">No threats found in this risk category.</p>
                        ) : (
                          getThreatsForCell(selectedMatrixCell.likelihood, selectedMatrixCell.impactScore).map(t => (
                            <div key={t.threat_id} className="p-3 bg-slate-50 dark:bg-slate-950/40 border border-slate-200 dark:border-border rounded-lg flex justify-between items-start gap-4">
                              <div className="space-y-1">
                                <span className="font-bold text-slate-800 dark:text-text block text-xs">{t.title}</span>
                                <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal">{t.description}</p>
                                {t.affected_components && (
                                  <span className="inline-block text-[9px] font-mono bg-slate-200 dark:bg-slate-800 text-slate-500 dark:text-slate-400 px-1.5 py-0.5 rounded mt-1">
                                    Element: {t.affected_components}
                                  </span>
                                )}
                              </div>
                              <span className="px-2 py-0.5 font-bold uppercase text-[9px] rounded bg-red-500/10 text-red-500 border border-red-500/20 whitespace-nowrap">
                                Score: {t.cvss_score || '0.0'}
                              </span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Floating Status Notification / Progress Bar */}
      {analysisState.status === 'running' && (
        <div className="fixed bottom-6 right-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-2xl p-5 z-50 max-w-sm w-full animate-in fade-in slide-in-from-bottom-5 duration-300">
          <div className="flex items-center gap-3 mb-3">
            <RefreshCw className="w-5 h-5 text-emerald-500 animate-spin" />
            <h4 className="text-sm font-bold text-slate-950 dark:text-white">AI Analysis in Progress...</h4>
          </div>
          <div className="space-y-2">
            <div className="flex justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
              <span>Iteration:</span>
              <span className="font-semibold text-slate-950 dark:text-white">
                {analysisState.current_iteration} / {analysisState.total_iterations}
              </span>
            </div>
            {analysisState.total_segments > 0 && (
              <>
                <div className="flex justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
                  <span>Segment Progress:</span>
                  <span className="font-semibold text-slate-950 dark:text-white">
                    {analysisState.current_segment} / {analysisState.total_segments}
                  </span>
                </div>
                <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-2 overflow-hidden">
                  <div
                    className="bg-emerald-500 h-full transition-all duration-500"
                    style={{ width: `${(analysisState.current_segment / analysisState.total_segments) * 100}%` }}
                  />
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Success Notification */}
      {showCompletionMessage && (
        <div className="fixed bottom-6 right-6 bg-white dark:bg-slate-900 border border-emerald-500/30 dark:border-emerald-500/20 rounded-xl shadow-2xl p-5 z-50 max-w-sm w-full animate-in fade-in slide-in-from-bottom-5 duration-300">
          <div className="flex items-start justify-between">
            <div className="flex gap-3">
              <div className="bg-emerald-500/10 p-1.5 rounded-lg border border-emerald-500/20">
                <Brain className="w-5 h-5 text-emerald-500" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-950 dark:text-white">Analysis Complete</h4>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  AI has completed threat modeling. {analysisState.new_threats} new threats identified and added to the project.
                </p>
              </div>
            </div>
            <button
              onClick={() => setShowCompletionMessage(false)}
              className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Error Notification */}
      {analysisState.status === 'failed' && analysisState.error && (
        <div className="fixed bottom-6 right-6 bg-white dark:bg-slate-900 border border-red-500/30 dark:border-red-500/20 rounded-xl shadow-2xl p-5 z-50 max-w-sm w-full animate-in fade-in slide-in-from-bottom-5 duration-300">
          <div className="flex items-start justify-between">
            <div className="flex gap-3">
              <div className="bg-red-500/10 p-1.5 rounded-lg border border-red-500/20">
                <ShieldAlert className="w-5 h-5 text-red-500" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-950 dark:text-white">Analysis Failed</h4>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  {analysisState.error}
                </p>
              </div>
            </div>
            <button
              onClick={() => setAnalysisState(prev => ({ ...prev, status: 'idle', error: null }))}
              className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Business Context Modal */}
      {isBusinessContextModalOpen && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-hidden flex flex-col">
            <div className="px-6 py-4 border-b border-slate-200 dark:border-border flex justify-between items-center bg-slate-50 dark:bg-slate-950">
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 flex items-center gap-2">
                <Briefcase className="w-4 h-4 text-primary-500" />
                Project Business Context
              </h3>
              <button
                onClick={() => setIsBusinessContextModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-6 space-y-4 overflow-y-auto">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Risk Preference</label>
                  <select
                    value={promptConfig.risk_preference}
                    onChange={(e) => setPromptConfig({ ...promptConfig, risk_preference: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border text-sm rounded-lg px-3 py-2 text-slate-800 dark:text-white focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition"
                  >
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Security Posture</label>
                  <select
                    value={promptConfig.security_posture}
                    onChange={(e) => setPromptConfig({ ...promptConfig, security_posture: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border text-sm rounded-lg px-3 py-2 text-slate-800 dark:text-white focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition"
                  >
                    <option value="Standard">Standard</option>
                    <option value="Hardened">Hardened</option>
                    <option value="Compliance-Driven">Compliance-Driven</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Compliance Priority</label>
                <input
                  type="text"
                  placeholder="e.g. GDPR, HIPAA, PCI-DSS"
                  value={promptConfig.compliance_priority}
                  onChange={(e) => setPromptConfig({ ...promptConfig, compliance_priority: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border text-sm rounded-lg px-3 py-2 text-slate-800 dark:text-white focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition placeholder:text-slate-400"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Industry Context</label>
                <input
                  type="text"
                  placeholder="e.g. Healthcare, Finance, E-commerce"
                  value={promptConfig.industry_context}
                  onChange={(e) => setPromptConfig({ ...promptConfig, industry_context: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border text-sm rounded-lg px-3 py-2 text-slate-800 dark:text-white focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition placeholder:text-slate-400"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Business Context Policy</label>
                <textarea
                  rows={3}
                  placeholder="Describe internal business policies related to security..."
                  value={promptConfig.business_context_policy}
                  onChange={(e) => setPromptConfig({ ...promptConfig, business_context_policy: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border text-sm rounded-lg px-3 py-2 text-slate-800 dark:text-white focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition placeholder:text-slate-400 resize-none"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Additional Global Instructions</label>
                <textarea
                  rows={4}
                  placeholder="Custom instructions for AI generation across the project..."
                  value={promptConfig.custom_prompt}
                  onChange={(e) => setPromptConfig({ ...promptConfig, custom_prompt: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border text-sm rounded-lg px-3 py-2 text-slate-800 dark:text-white focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition placeholder:text-slate-400 resize-none"
                />
              </div>
            </div>
            <div className="px-6 py-4 border-t border-slate-200 dark:border-border bg-slate-50 dark:bg-slate-950 flex justify-end gap-3">
              <button
                onClick={() => setIsBusinessContextModalOpen(false)}
                className="px-4 py-2 text-sm font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={savePromptConfig}
                className="px-4 py-2 text-sm font-semibold bg-primary-600 hover:bg-primary-500 text-white rounded-lg shadow-md transition"
              >
                Save Configuration
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Configure AI Modal */}
      {isConfigModalOpen && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-2xl max-w-md w-full overflow-hidden flex flex-col">
            <div className="px-6 py-4 border-b border-slate-200 dark:border-border flex justify-between items-center bg-slate-50 dark:bg-slate-950">
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 flex items-center gap-2">
                <Settings className="w-4 h-4 text-primary-500" />
                Configure AI Provider
              </h3>
              <button
                onClick={() => setIsConfigModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-6 space-y-4 overflow-y-auto">
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                  Provider
                </label>
                <select
                  value={providerType}
                  onChange={(e) => {
                    setProviderType(e.target.value);
                    if (e.target.value === 'ollama') {
                      fetchOllamaModels();
                    } else {
                      setModelName('gemini-3.1-flash-lite-preview');
                    }
                  }}
                  className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold focus:outline-none focus:border-primary-500 text-slate-800 dark:text-white"
                >
                  <option value="ollama">Ollama (Local AI)</option>
                  <option value="gemini">Google Gemini (Cloud AI)</option>
                </select>
              </div>

              {providerType === 'ollama' ? (
                <>
                  <div className="space-y-1.5">
                    <label className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                      Ollama Endpoint URL
                    </label>
                    <input
                      type="text"
                      value={endpointUrl}
                      onChange={(e) => setEndpointUrl(e.target.value)}
                      placeholder="http://localhost:11434"
                      className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold font-mono focus:outline-none focus:border-primary-500 text-slate-800 dark:text-white"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider flex items-center gap-2">
                      Model Name
                      {ollamaModelsLoading && <span className="text-[10px] text-primary-500 font-normal animate-pulse">Fetching models…</span>}
                    </label>
                    {ollamaModels.length > 0 ? (
                      <select
                        value={modelName}
                        onChange={(e) => setModelName(e.target.value)}
                        className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold font-mono focus:outline-none focus:border-primary-500 text-slate-800 dark:text-white"
                      >
                        {ollamaModels.map(m => (
                          <option key={m} value={m}>{m}</option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type="text"
                        value={modelName}
                        onChange={(e) => setModelName(e.target.value)}
                        placeholder={ollamaModelsLoading ? "Loading..." : "qwen2.5-coder:7b (no models found)"}
                        className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold font-mono focus:outline-none focus:border-primary-500 text-slate-800 dark:text-white"
                      />
                    )}
                    {!ollamaModelsLoading && ollamaModels.length === 0 && (
                      <button
                        onClick={fetchOllamaModels}
                        className="text-[10px] text-primary-500 hover:text-primary-400 font-semibold transition"
                      >
                        ↻ Retry fetching models
                      </button>
                    )}
                  </div>
                </>
              ) : (
                <>
                  <div className="space-y-1.5">
                    <label className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                      Gemini API Key
                    </label>
                    <input
                      type="password"
                      value={geminiApiKey}
                      onChange={(e) => setGeminiApiKey(e.target.value)}
                      placeholder="AIzaSy..."
                      className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold font-mono focus:outline-none focus:border-primary-500 text-slate-800 dark:text-white"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                      Model Name
                    </label>
                    <select
                      value={modelName}
                      onChange={(e) => setModelName(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold focus:outline-none focus:border-primary-500 text-slate-800 dark:text-white"
                    >
                      <option value="gemini-3.1-flash-lite-preview">gemini-3.1-flash-lite-preview</option>
                      <option value="gemini-3.1-flash-lite">gemini-3.1-flash-lite</option>
                      <option value="gemini-2.0-flash">gemini-2.0-flash</option>
                      <option value="gemini-1.5-flash">gemini-1.5-flash</option>
                    </select>
                  </div>
                </>
              )}

              <div className="space-y-1.5 pt-2 border-t border-slate-200 dark:border-border">
                <label className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                  Max Tokens
                </label>
                <select
                  value={maxTokens}
                  onChange={(e) => setMaxTokens(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold focus:outline-none focus:border-primary-500 text-slate-800 dark:text-white"
                >
                  <option value={8192}>8192</option>
                  <option value={16384}>16384</option>
                  <option value={32768}>32768</option>
                </select>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-slate-200 dark:border-border bg-slate-50 dark:bg-slate-950 flex justify-end gap-3">
              <button
                onClick={() => setIsConfigModalOpen(false)}
                className="px-4 py-2 bg-slate-200 hover:bg-slate-300 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-semibold rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={saveAIConfig}
                className="px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white text-xs font-semibold rounded-lg shadow-md transition"
              >
                Save Config
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Run AI Analysis Modal */}
      {isAnalysisModalOpen && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-2xl max-w-md w-full overflow-hidden flex flex-col">
            <div className="px-6 py-4 border-b border-slate-200 dark:border-border flex justify-between items-center bg-slate-50 dark:bg-slate-950">
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 flex items-center gap-2">
                <Brain className="w-4 h-4 text-emerald-500" />
                Run AI Threat Analysis
              </h3>
              <button
                onClick={() => setIsAnalysisModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-6 space-y-4 overflow-y-auto">
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                  Analysis Mode
                </label>
                <select
                  value={analysisMode}
                  onChange={(e) => setAnalysisMode(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold focus:outline-none focus:border-primary-500 text-slate-800 dark:text-white"
                >
                  <option value="STRIDE">STRIDE (Threat Modeling)</option>
                  <option value="LINDDUN">LINDDUN (Privacy Threat Modeling)</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                  Iterations (1 - 5)
                </label>
                <select
                  value={iterations}
                  onChange={(e) => setIterations(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold focus:outline-none focus:border-primary-500 text-slate-800 dark:text-white"
                >
                  <option value={1}>1 (Single Pass)</option>
                  <option value={2}>2 Passes (Refined Analysis)</option>
                  <option value={3}>3 Passes</option>
                  <option value={4}>4 Passes</option>
                  <option value={5}>5 Passes (Deep Analysis)</option>
                </select>
              </div>

              <div className="flex gap-2.5 p-3.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded-lg">
                <Info className="w-4 h-4 text-primary-500 shrink-0 mt-0.5" />
                <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal">
                  Running multiple iterations refines the identified threats by performing sequential reviews.
                  Analysis runs as a background process and might take up to several minutes depending on the model.
                </p>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-slate-200 dark:border-border bg-slate-50 dark:bg-slate-950 flex justify-end gap-3">
              <button
                onClick={() => setIsAnalysisModalOpen(false)}
                className="px-4 py-2 bg-slate-200 hover:bg-slate-300 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-semibold rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={runAIAnalysis}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg shadow-md transition"
              >
                Run Analysis
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Edit Threat Modal */}
      {editingThreat && (
        <div className="fixed inset-0 bg-slate-950/40 backdrop-blur-sm flex items-center justify-center z-50 animate-in fade-in duration-205">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-2xl max-w-2xl w-full p-6 shadow-2xl flex flex-col gap-4 max-h-[90vh] overflow-y-auto select-text">
            <div className="flex justify-between items-center pb-3 border-b border-slate-200 dark:border-border">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-amber-500" />
                Edit Threat & Risk Metrics
              </h3>
              <button
                onClick={() => setEditingThreat(null)}
                className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-700 rounded-lg transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="block font-bold text-slate-700 dark:text-slate-300">Threat Title</label>
                  <input
                    type="text"
                    value={editingThreat.title || ''}
                    onChange={(e) => setEditingThreat({ ...editingThreat, title: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2.5 py-1.5 text-slate-800 dark:text-white"
                  />
                </div>
                <div className="space-y-1">
                  <label className="block font-bold text-slate-700 dark:text-slate-300">Category</label>
                  <select
                    value={editingThreat.category || 'Spoofing'}
                    onChange={(e) => setEditingThreat({ ...editingThreat, category: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2.5 py-1.5 text-slate-850 dark:text-white"
                  >
                    <option value="Spoofing">Spoofing</option>
                    <option value="Tampering">Tampering</option>
                    <option value="Repudiation">Repudiation</option>
                    <option value="Information Disclosure">Information Disclosure</option>
                    <option value="Denial of Service">Denial of Service</option>
                    <option value="Elevation of Privilege">Elevation of Privilege</option>
                    <option value="Linkability">Linkability</option>
                    <option value="Identifiability">Identifiability</option>
                    <option value="Non-repudiation">Non-repudiation</option>
                    <option value="Detectability">Detectability</option>
                    <option value="Disclosure of Information">Disclosure of Information</option>
                    <option value="Unawareness">Unawareness</option>
                    <option value="Non-compliance">Non-compliance</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="block font-bold text-slate-700 dark:text-slate-300">Description</label>
                <textarea
                  value={editingThreat.description || ''}
                  onChange={(e) => setEditingThreat({ ...editingThreat, description: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2.5 py-1.5 text-slate-700 dark:text-slate-300 resize-none h-16"
                />
              </div>

              <div className="space-y-1">
                <label className="block font-bold text-slate-700 dark:text-slate-300">Mitigation Requirement</label>
                <textarea
                  value={editingThreat.mitigation || ''}
                  onChange={(e) => setEditingThreat({ ...editingThreat, mitigation: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2.5 py-1.5 text-slate-700 dark:text-slate-300 resize-none h-16"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="block font-bold text-slate-700 dark:text-slate-300">Affected Components</label>
                  <input
                    type="text"
                    value={editingThreat.affected_components || ''}
                    onChange={(e) => setEditingThreat({ ...editingThreat, affected_components: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2.5 py-1.5 text-slate-800 dark:text-white"
                  />
                </div>
                <div className="space-y-1">
                  <label className="block font-bold text-slate-700 dark:text-slate-300">MITRE ATT&CK ID</label>
                  <input
                    type="text"
                    value={editingThreat.mitre_attack_id || ''}
                    onChange={(e) => setEditingThreat({ ...editingThreat, mitre_attack_id: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2.5 py-1.5 text-slate-800 dark:text-white"
                  />
                </div>
              </div>

              {/* CVSS Metric Selectors */}
              <div className="border border-slate-200 dark:border-border p-4 rounded-xl space-y-3 bg-slate-50/50 dark:bg-slate-950/20">
                <div className="flex justify-between items-center border-b border-slate-200 dark:border-border pb-1.5">
                  <span className="font-bold text-slate-800 dark:text-slate-200">CVSS v3.1 Calculator</span>
                  <span className="font-bold text-red-500 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20 font-mono">
                    Score: {editingThreat.cvss_score || 0}
                  </span>
                </div>

                <div className="grid grid-cols-4 gap-3">
                  <div>
                    <label className="block text-[10px] font-semibold text-slate-550 mb-1">AV (Attack Vector)</label>
                    <select
                      value={parseCVSSVector(editingThreat.cvss_vector).AV}
                      onChange={(e) => {
                        const m = parseCVSSVector(editingThreat.cvss_vector);
                        m.AV = e.target.value as any;
                        const vec = generateCVSSVector(m);
                        const score = calculateCVSSBaseScore(m);
                        setEditingThreat({ ...editingThreat, cvss_vector: vec, cvss_score: score });
                      }}
                      className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-1 rounded text-slate-800 dark:text-white"
                    >
                      <option value="N">Network (N)</option>
                      <option value="A">Adjacent (A)</option>
                      <option value="L">Local (L)</option>
                      <option value="P">Physical (P)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] font-semibold text-slate-550 mb-1">AC (Complexity)</label>
                    <select
                      value={parseCVSSVector(editingThreat.cvss_vector).AC}
                      onChange={(e) => {
                        const m = parseCVSSVector(editingThreat.cvss_vector);
                        m.AC = e.target.value as any;
                        const vec = generateCVSSVector(m);
                        const score = calculateCVSSBaseScore(m);
                        setEditingThreat({ ...editingThreat, cvss_vector: vec, cvss_score: score });
                      }}
                      className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-1 rounded text-slate-800 dark:text-white"
                    >
                      <option value="L">Low (L)</option>
                      <option value="H">High (H)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] font-semibold text-slate-550 mb-1">PR (Privileges)</label>
                    <select
                      value={parseCVSSVector(editingThreat.cvss_vector).PR}
                      onChange={(e) => {
                        const m = parseCVSSVector(editingThreat.cvss_vector);
                        m.PR = e.target.value as any;
                        const vec = generateCVSSVector(m);
                        const score = calculateCVSSBaseScore(m);
                        setEditingThreat({ ...editingThreat, cvss_vector: vec, cvss_score: score });
                      }}
                      className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-1 rounded text-slate-800 dark:text-white"
                    >
                      <option value="N">None (N)</option>
                      <option value="L">Low (L)</option>
                      <option value="H">High (H)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] font-semibold text-slate-550 mb-1">UI (Interaction)</label>
                    <select
                      value={parseCVSSVector(editingThreat.cvss_vector).UI}
                      onChange={(e) => {
                        const m = parseCVSSVector(editingThreat.cvss_vector);
                        m.UI = e.target.value as any;
                        const vec = generateCVSSVector(m);
                        const score = calculateCVSSBaseScore(m);
                        setEditingThreat({ ...editingThreat, cvss_vector: vec, cvss_score: score });
                      }}
                      className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-1 rounded text-slate-800 dark:text-white"
                    >
                      <option value="N">None (N)</option>
                      <option value="R">Required (R)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] font-semibold text-slate-550 mb-1">S (Scope)</label>
                    <select
                      value={parseCVSSVector(editingThreat.cvss_vector).S}
                      onChange={(e) => {
                        const m = parseCVSSVector(editingThreat.cvss_vector);
                        m.S = e.target.value as any;
                        const vec = generateCVSSVector(m);
                        const score = calculateCVSSBaseScore(m);
                        setEditingThreat({ ...editingThreat, cvss_vector: vec, cvss_score: score });
                      }}
                      className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-1 rounded text-slate-800 dark:text-white"
                    >
                      <option value="U">Unchanged (U)</option>
                      <option value="C">Changed (C)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] font-semibold text-slate-550 mb-1">C (Confidentiality)</label>
                    <select
                      value={parseCVSSVector(editingThreat.cvss_vector).C}
                      onChange={(e) => {
                        const m = parseCVSSVector(editingThreat.cvss_vector);
                        m.C = e.target.value as any;
                        const vec = generateCVSSVector(m);
                        const score = calculateCVSSBaseScore(m);
                        setEditingThreat({ ...editingThreat, cvss_vector: vec, cvss_score: score });
                      }}
                      className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-1 rounded text-slate-800 dark:text-white"
                    >
                      <option value="N">None (N)</option>
                      <option value="L">Low (L)</option>
                      <option value="H">High (H)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] font-semibold text-slate-550 mb-1">I (Integrity)</label>
                    <select
                      value={parseCVSSVector(editingThreat.cvss_vector).I}
                      onChange={(e) => {
                        const m = parseCVSSVector(editingThreat.cvss_vector);
                        m.I = e.target.value as any;
                        const vec = generateCVSSVector(m);
                        const score = calculateCVSSBaseScore(m);
                        setEditingThreat({ ...editingThreat, cvss_vector: vec, cvss_score: score });
                      }}
                      className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-1 rounded text-slate-800 dark:text-white"
                    >
                      <option value="N">None (N)</option>
                      <option value="L">Low (L)</option>
                      <option value="H">High (H)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] font-semibold text-slate-550 mb-1">A (Availability)</label>
                    <select
                      value={parseCVSSVector(editingThreat.cvss_vector).A}
                      onChange={(e) => {
                        const m = parseCVSSVector(editingThreat.cvss_vector);
                        m.A = e.target.value as any;
                        const vec = generateCVSSVector(m);
                        const score = calculateCVSSBaseScore(m);
                        setEditingThreat({ ...editingThreat, cvss_vector: vec, cvss_score: score });
                      }}
                      className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-1 rounded text-slate-800 dark:text-white"
                    >
                      <option value="N">None (N)</option>
                      <option value="L">Low (L)</option>
                      <option value="H">High (H)</option>
                    </select>
                  </div>
                </div>

                <div className="text-[10px] font-mono bg-slate-100 dark:bg-slate-950 p-2 rounded break-all leading-normal text-slate-500 select-all border border-slate-200/50 dark:border-border/30">
                  Vector String: {editingThreat.cvss_vector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}
                </div>

                <div className="mt-2">
                  <label className="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-1">CVSS Modification Rationale</label>
                  <textarea
                    value={editingThreat.cvss_rationale || ''}
                    onChange={(e) => setEditingThreat({ ...editingThreat, cvss_rationale: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500 h-16 resize-none"
                    placeholder="Provide justification if you are manually modifying the AI-suggested CVSS vector..."
                  />
                </div>
              </div>

              {/* Accepted Risk Toggle */}
              <div className="flex flex-col gap-2 p-3 border border-slate-200 dark:border-border rounded-xl">
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={editingThreat.is_accepted_risk || false}
                    onChange={(e) => setEditingThreat({ ...editingThreat, is_accepted_risk: e.target.checked })}
                    className="w-4 h-4 accent-primary-500"
                    id="modal-risk-accepted"
                  />
                  <label htmlFor="modal-risk-accepted" className="font-bold text-slate-800 dark:text-slate-350 cursor-pointer">Accept Risk</label>
                </div>
                {editingThreat.is_accepted_risk && (
                  <div className="space-y-1 mt-1">
                    <label className="block font-bold text-slate-700 dark:text-slate-300">Acceptance Justification</label>
                    <textarea
                      value={editingThreat.acceptance_justification || ''}
                      onChange={(e) => setEditingThreat({ ...editingThreat, acceptance_justification: e.target.value })}
                      placeholder="Provide business justification for accepting this threat risk..."
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2.5 py-1.5 text-slate-700 dark:text-slate-300 resize-none h-12"
                    />
                  </div>
                )}
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-slate-200 dark:border-border bg-slate-50 dark:bg-slate-950 -mx-6 -mb-6 p-4 rounded-b-2xl">
              <button
                onClick={() => setEditingThreat(null)}
                className="px-4 py-2 border border-slate-200 dark:border-border text-slate-700 dark:text-slate-300 rounded-lg font-semibold hover:bg-slate-100 dark:hover:bg-slate-800 transition text-xs"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  updateThreat(editingThreat.threat_id, editingThreat);
                  setEditingThreat(null);
                }}
                className="px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-lg font-semibold shadow-md transition text-xs"
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}
      {/* xAI Reasoning Modal */}
      {reasoningModalContent && (
        <div className="fixed inset-0 bg-slate-950/40 backdrop-blur-sm flex items-center justify-center z-50 animate-in fade-in duration-205">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-2xl max-w-xl w-full p-6 shadow-2xl flex flex-col gap-4 select-text">
            <div className="flex justify-between items-center pb-3 border-b border-slate-200 dark:border-border">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-emerald-500" />
                {reasoningModalTitle || 'XAI Technical Reasoning'}
              </h3>
              <button
                onClick={() => {
                  setReasoningModalContent(null);
                  setReasoningModalTitle(null);
                }}
                className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-700 rounded-lg transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="overflow-y-auto max-h-[60vh] pr-2 text-xs">
              {(() => {
                let clean = reasoningModalContent.trim();
                if (clean.startsWith('```json')) {
                  clean = clean.substring(7);
                } else if (clean.startsWith('```')) {
                  clean = clean.substring(3);
                }
                if (clean.endsWith('```')) {
                  clean = clean.substring(0, clean.length - 3);
                }
                clean = clean.trim();
                try {
                  const parsed = JSON.parse(clean);
                  return (
                    <div className="space-y-4">
                      {parsed.attack_vector && (
                        <div>
                          <span className="font-bold text-red-500 text-[10px] uppercase tracking-wider block">Attack Vector</span>
                          <p className="text-xs text-slate-705 dark:text-slate-300 mt-1 leading-relaxed">{parsed.attack_vector}</p>
                        </div>
                      )}
                      {parsed.architectural_root_cause && (
                        <div className="border-t border-slate-200 dark:border-border/30 pt-3">
                          <span className="font-bold text-amber-500 text-[10px] uppercase tracking-wider block">Architectural Root Cause</span>
                          <p className="text-xs text-slate-705 dark:text-slate-300 mt-1 leading-relaxed">{parsed.architectural_root_cause}</p>
                        </div>
                      )}
                      {parsed.risk_rationalization && (
                        <div className="border-t border-slate-200 dark:border-border/30 pt-3">
                          <span className="font-bold text-primary-500 text-[10px] uppercase tracking-wider block">Risk Rationalization</span>
                          <p className="text-xs text-slate-705 dark:text-slate-300 mt-1 leading-relaxed">{parsed.risk_rationalization}</p>
                        </div>
                      )}
                      {parsed.framework_alignment && (
                        <div className="border-t border-slate-200 dark:border-border/30 pt-3">
                          <span className="font-bold text-emerald-500 text-[10px] uppercase tracking-wider block">Framework Alignment</span>
                          <p className="text-xs text-slate-705 dark:text-slate-300 mt-1 leading-relaxed">{parsed.framework_alignment}</p>
                        </div>
                      )}
                    </div>
                  );
                } catch (e) {
                  return renderMarkdown(reasoningModalContent);
                }
              })()}
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-200 dark:border-border bg-slate-50 dark:bg-slate-950 -mx-6 -mb-6 p-4 rounded-b-2xl">
              <button
                onClick={() => {
                  setReasoningModalContent(null);
                  setReasoningModalTitle(null);
                }}
                className="px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-lg font-semibold shadow-md transition text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Edit Vulnerability Modal */}
      {editingVuln && (
        <div className="fixed inset-0 bg-slate-950/40 backdrop-blur-sm flex items-center justify-center z-50 animate-in fade-in duration-205">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-2xl max-w-xl w-full p-6 shadow-2xl flex flex-col gap-4 select-text">
            <div className="flex justify-between items-center pb-3 border-b border-slate-200 dark:border-border">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-red-500" />
                Edit Vulnerability Details
              </h3>
              <button
                onClick={() => setEditingVuln(null)}
                className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-700 rounded-lg transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="block font-bold text-slate-700 dark:text-slate-300">Vulnerability Title</label>
                  <input
                    type="text"
                    value={editingVuln.title || ''}
                    onChange={(e) => setEditingVuln({ ...editingVuln, title: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2.5 py-1.5 text-slate-800 dark:text-white"
                  />
                </div>
                <div className="space-y-1">
                  <label className="block font-bold text-slate-700 dark:text-slate-300">Status</label>
                  <select
                    value={editingVuln.status || 'Open'}
                    onChange={(e) => setEditingVuln({ ...editingVuln, status: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2.5 py-1.5 text-slate-850 dark:text-white"
                  >
                    <option value="Open">Open</option>
                    <option value="Remediated">Remediated</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="block font-bold text-slate-700 dark:text-slate-300">Description</label>
                <textarea
                  value={editingVuln.description || ''}
                  onChange={(e) => setEditingVuln({ ...editingVuln, description: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2.5 py-1.5 text-slate-700 dark:text-slate-300 resize-none h-20"
                />
              </div>

              <div className="space-y-1">
                <label className="block font-bold text-slate-700 dark:text-slate-300">Mitigation Description</label>
                <textarea
                  value={editingVuln.mitigation || ''}
                  onChange={(e) => setEditingVuln({ ...editingVuln, mitigation: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2.5 py-1.5 text-slate-700 dark:text-slate-300 resize-none h-20"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-slate-200 dark:border-border bg-slate-50 dark:bg-slate-950 -mx-6 -mb-6 p-4 rounded-b-2xl">
              <button
                onClick={() => setEditingVuln(null)}
                className="px-4 py-2 border border-slate-200 dark:border-border text-slate-700 dark:text-slate-300 rounded-lg font-semibold hover:bg-slate-100 dark:hover:bg-slate-800 transition text-xs"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  updateVulnerability(editingVuln.vulnerability_id, editingVuln);
                  setEditingVuln(null);
                }}
                className="px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-lg font-semibold shadow-md transition text-xs"
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}
      {isAddingThreat && <AddThreatModal onClose={() => setIsAddingThreat(false)} />}
      {isAddingRisk && <AddRiskModal onClose={() => setIsAddingRisk(false)} />}
      {isAddingVuln && <AddVulnerabilityModal onClose={() => setIsAddingVuln(false)} />}
      {isAddingMitigation && (
        <AddMitigationModal onClose={() => setIsAddingMitigation(false)} />
      )}
      {isJiraSettingsOpen && (
        <JiraSettingsModal onClose={() => setIsJiraSettingsOpen(false)} />
      )}
      
      {/* Narrative Modal */}
      {isNarrativeModalOpen && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-sm z-50 flex items-center justify-center p-6">
          <div className="bg-white dark:bg-slate-900 rounded-xl shadow-2xl w-full max-w-3xl flex flex-col max-h-[85vh] border border-slate-200 dark:border-border">
            <div className="flex justify-between items-center p-5 border-b border-slate-200 dark:border-border bg-slate-50 dark:bg-slate-950/50 rounded-t-xl shrink-0">
              <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <FileSpreadsheet className="w-5 h-5 text-indigo-500" />
                Architecture Narrative
              </h2>
              <div className="flex items-center gap-2">
                {narrativeText && (
                  <button 
                    onClick={() => {
                      navigator.clipboard.writeText(narrativeText);
                      alert('Copied to clipboard');
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-500/20 text-xs font-semibold rounded-lg hover:bg-indigo-100 dark:hover:bg-indigo-500/20 transition"
                  >
                    <Save className="w-3.5 h-3.5" />
                    Copy
                  </button>
                )}
                <button
                  onClick={() => setIsNarrativeModalOpen(false)}
                  className="p-1.5 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-lg text-slate-500 transition"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>
            
            <div className="p-6 overflow-y-auto flex-1 bg-slate-50 dark:bg-slate-950/20">
              {isGeneratingNarrative ? (
                <div className="flex flex-col items-center justify-center h-48 space-y-4">
                  <RefreshCw className="w-8 h-8 text-indigo-500 animate-spin" />
                  <p className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Generating technical story from architecture...
                  </p>
                </div>
              ) : narrativeText ? (
                <div className="prose dark:prose-invert max-w-none text-sm text-slate-700 dark:text-slate-300">
                  {renderMarkdown(narrativeText)}
                </div>
              ) : (
                <p className="text-center text-slate-500">No narrative generated.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
