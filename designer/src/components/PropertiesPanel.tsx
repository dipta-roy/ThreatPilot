import React from 'react';
import { useDesignerStore, parseCVSSVector, generateCVSSVector, calculateCVSSBaseScore } from '../store/useDesignerStore';
import { Trash2, Plus, ShieldAlert, KeyRound, Globe, FileText, CheckCircle2, Shield, Edit, Sparkles } from 'lucide-react';

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
    <div className="space-y-2.5 leading-relaxed text-slate-650 dark:text-slate-350 select-text text-[10px]">
      {lines.map((line, idx) => {
        const trimmed = line.trim();
        
        // Horizontal rule
        if (trimmed === '---') {
          return <hr key={idx} className="border-t border-slate-200 dark:border-border/30 my-3" />;
        }
        
        // Headers
        if (trimmed.startsWith('# ')) {
          return <h1 key={idx} className="text-xs font-extrabold text-slate-900 dark:text-white mt-3 mb-1.5">{trimmed.substring(2)}</h1>;
        }
        if (trimmed.startsWith('## ')) {
          return <h2 key={idx} className="text-[11px] font-bold text-slate-900 dark:text-white mt-3 mb-1.5">{trimmed.substring(3)}</h2>;
        }
        if (trimmed.startsWith('### ')) {
          return <h3 key={idx} className="text-[10px] font-bold text-slate-900 dark:text-white mt-2 mb-1">{trimmed.substring(4)}</h3>;
        }
        if (trimmed.startsWith('#### ')) {
          return <h4 key={idx} className="text-[9px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mt-2 mb-1">{trimmed.substring(5)}</h4>;
        }
        
        // Bullet points
        if (trimmed.startsWith('* ') || trimmed.startsWith('- ')) {
          const content = trimmed.substring(2);
          return (
            <li key={idx} className="ml-3 list-disc pl-0.5 text-[10px]">
              {renderInlineBold(content)}
            </li>
          );
        }

        // Ordered lists
        const matchOrdered = trimmed.match(/^(\d+)\.\s+(.*)$/);
        if (matchOrdered) {
          return (
            <li key={idx} className="ml-3 list-decimal pl-0.5 text-[10px]">
              {renderInlineBold(matchOrdered[2])}
            </li>
          );
        }

        // Normal paragraph
        if (trimmed === '') {
          return <div key={idx} className="h-0.5" />;
        }
        
        return <p key={idx} className="text-[10px]">{renderInlineBold(line)}</p>;
      })}
    </div>
  );
};

export default function PropertiesPanel() {
  const {
    nodes,
    edges,
    assets,
    selectedElementId,
    selectedElementType,
    updateComponent,
    updateBoundary,
    updateFlow,
    updateAsset,
    addAsset,
    deleteElement,
    threats,
    vulnerabilities,
    updateThreat,
    deleteThreat,
    updateVulnerability,
    deleteVulnerability
  } = useDesignerStore();

  const [editingThreatId, setEditingThreatId] = React.useState<string | null>(null);
  const [editingVulnId, setEditingVulnId] = React.useState<string | null>(null);
  const [generatingReasoningId, setGeneratingReasoningId] = React.useState<string | null>(null);

  const [sidebarWidth, setSidebarWidth] = React.useState(350);
  const isResizing = React.useRef(false);

  const startResize = (e: React.MouseEvent) => {
    e.preventDefault();
    isResizing.current = true;
    document.addEventListener('mousemove', handleResize);
    document.addEventListener('mouseup', stopResize);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  const handleResize = React.useCallback((e: MouseEvent) => {
    if (!isResizing.current) return;
    const newWidth = window.innerWidth - e.clientX;
    if (newWidth > 260 && newWidth < 800) {
      setSidebarWidth(newWidth);
    }
  }, []);

  const stopResize = React.useCallback(() => {
    isResizing.current = false;
    document.removeEventListener('mousemove', handleResize);
    document.removeEventListener('mouseup', stopResize);
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  }, [handleResize]);

  React.useEffect(() => {
    return () => {
      document.removeEventListener('mousemove', handleResize);
      document.removeEventListener('mouseup', stopResize);
    };
  }, [handleResize, stopResize]);

  const generateReasoning = async (threatId?: string, vulnId?: string) => {
    const targetId = threatId || vulnId;
    if (!targetId) return;
    
    setGeneratingReasoningId(targetId);
    try {
      const res = await fetch('/api/ai/reason', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threat_id: threatId, vulnerability_id: vulnId })
      });
      if (res.ok) {
        const data = await res.json();
        if (threatId) {
          updateThreat(threatId, { reasoning: data.reasoning });
        } else if (vulnId) {
          updateVulnerability(vulnId, { reasoning: data.reasoning });
        }
      } else {
        const err = await res.json();
        alert(err.error || 'Failed to generate reasoning');
      }
    } catch (e) {
      console.error(e);
      alert('Error generating reasoning');
    } finally {
      setGeneratingReasoningId(null);
    }
  };

  const renderReasoning = (reasoning: string) => {
    try {
      let clean = reasoning.trim();
      if (clean.startsWith('```json')) {
        clean = clean.substring(7);
      }
      if (clean.endsWith('```')) {
        clean = clean.substring(0, clean.length - 3);
      }
      clean = clean.trim();
      
      const parsed = JSON.parse(clean);
      return (
        <div className="space-y-2 mt-1 select-text">
          {parsed.attack_vector && (
            <div>
              <span className="font-bold text-red-500 text-[9px] uppercase tracking-wider block">Attack Vector</span>
              <p className="text-[10px] text-slate-700 dark:text-slate-300 mt-0.5 leading-normal">{parsed.attack_vector}</p>
            </div>
          )}
          {parsed.architectural_root_cause && (
            <div className="border-t border-slate-200 dark:border-border/30 pt-1.5">
              <span className="font-bold text-amber-500 text-[9px] uppercase tracking-wider block">Architectural Root Cause</span>
              <p className="text-[10px] text-slate-700 dark:text-slate-300 mt-0.5 leading-normal">{parsed.architectural_root_cause}</p>
            </div>
          )}
          {parsed.risk_rationalization && (
            <div className="border-t border-slate-200 dark:border-border/30 pt-1.5">
              <span className="font-bold text-primary-500 text-[9px] uppercase tracking-wider block">Risk Rationalization</span>
              <p className="text-[10px] text-slate-700 dark:text-slate-300 mt-0.5 leading-normal">{parsed.risk_rationalization}</p>
            </div>
          )}
          {parsed.framework_alignment && (
            <div className="border-t border-slate-200 dark:border-border/30 pt-1.5">
              <span className="font-bold text-emerald-500 text-[9px] uppercase tracking-wider block">Framework Alignment</span>
              <p className="text-[10px] text-slate-700 dark:text-slate-300 mt-0.5 leading-normal">{parsed.framework_alignment}</p>
            </div>
          )}
        </div>
      );
    } catch (e) {
      return renderMarkdown(reasoning);
    }
  };

  const getSelectedNames = () => {
    const names: string[] = [];
    const singleNode = selectedElementId ? nodes.find(n => n.id === selectedElementId) : null;
    const singleEdge = selectedElementId ? edges.find(e => e.id === selectedElementId) : null;
    
    let activeNodes = nodes.filter(n => n.selected);
    if (activeNodes.length === 0 && singleNode) {
      activeNodes = [singleNode];
    }
    
    let activeEdges = edges.filter(e => e.selected);
    if (activeEdges.length === 0 && singleEdge) {
      activeEdges = [singleEdge];
    }
    
    activeNodes.forEach(n => {
      if (n.data?.name) {
        names.push(n.data.name.trim().toLowerCase());
        if (n.type === 'boundaryNode') {
          nodes.forEach(c => {
            if (c.type === 'componentNode' && c.data?.trust_boundary_id === n.id && c.data?.name) {
              names.push(c.data.name.trim().toLowerCase());
            }
          });
        }
      }
    });
    
    activeEdges.forEach(e => {
      if (e.data?.name) {
        names.push(e.data.name.trim().toLowerCase());
      }
    });
    
    return names;
  };

  const selectedNames = getSelectedNames();
  
  const filteredThreats = threats.filter(t => {
    if (selectedNames.length === 0) return false;
    const aff = (t.affected_components || '').toLowerCase();
    return selectedNames.some(name => aff.includes(name));
  });

  const selectedNodes = nodes.filter((n) => n.selected);
  const selectedEdges = edges.filter((e) => e.selected);
  const isMultiSelection = (selectedNodes.length + selectedEdges.length) > 1;

  const renderThreatsSection = () => {
    if (selectedNames.length === 0) return null;
    
    return (
      <div className="border-t border-slate-200 dark:border-border pt-4 mt-4 flex flex-col gap-4">
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
          <Shield className="w-4 h-4 text-amber-500" />
          Threats & Risks ({filteredThreats.length})
        </h4>
        
        {filteredThreats.length === 0 ? (
          <p className="text-xs text-slate-400 italic">No threats identified for selected elements.</p>
        ) : (
          <div className="space-y-3">
            {filteredThreats.map(t => {
              const linkedVulns = vulnerabilities.filter(v => t.vulnerability_ids?.includes(v.vulnerability_id));
              const isEditing = editingThreatId === t.threat_id;
              const isGenerating = generatingReasoningId === t.threat_id;
              
              return (
                <div key={t.threat_id} className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border p-3 rounded-lg flex flex-col gap-2 relative group">
                  
                  {/* Action buttons */}
                  <div className="absolute top-2 right-2 flex items-center gap-1.5 opacity-0 group-hover:opacity-100 transition">
                    <button
                      onClick={() => generateReasoning(t.threat_id, undefined)}
                      disabled={isGenerating}
                      className="text-slate-500 hover:text-emerald-500 transition disabled:opacity-50"
                      title="Generate AI Technical Reasoning (XAI)"
                    >
                      <Sparkles className={`w-3 h-3 ${isGenerating ? 'animate-pulse text-emerald-500' : ''}`} />
                    </button>
                    <button
                      onClick={() => setEditingThreatId(isEditing ? null : t.threat_id)}
                      className="text-slate-500 hover:text-primary-500 transition"
                      title="Edit Threat"
                    >
                      <Edit className="w-3 h-3" />
                    </button>
                    <button
                      onClick={() => { if (confirm('Delete this threat?')) deleteThreat(t.threat_id); }}
                      className="text-slate-500 hover:text-red-400 transition"
                      title="Delete Threat"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>

                  <div className="flex justify-between items-start gap-2 pr-16">
                    {isEditing ? (
                      <select
                        value={t.category}
                        onChange={(e) => updateThreat(t.threat_id, { category: e.target.value })}
                        className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-[10px] text-slate-800 dark:text-white rounded p-1"
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
                    ) : (
                      <span className="px-1.5 py-0.5 bg-amber-500/10 text-amber-500 text-[9px] font-bold uppercase tracking-wider rounded border border-amber-500/20">
                        {t.category}
                      </span>
                    )}
                    {isEditing ? (
                      <span className="text-[10px] font-mono font-bold text-slate-500 bg-slate-100 dark:bg-slate-950 px-1.5 py-0.5 rounded">
                        Score: {t.cvss_score || 0}
                      </span>
                    ) : (
                      t.cvss_score > 0 && (
                        <span className="text-[10px] font-mono text-slate-400">
                          CVSS: {t.cvss_score}
                        </span>
                      )
                    )}
                  </div>

                  {isEditing ? (
                    <div className="space-y-2 mt-1">
                      <input
                        type="text"
                        value={t.title}
                        onChange={(e) => updateThreat(t.threat_id, { title: e.target.value })}
                        className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-xs rounded p-1 text-slate-800 dark:text-white"
                        placeholder="Threat Title"
                      />
                      <textarea
                        value={t.description}
                        onChange={(e) => updateThreat(t.threat_id, { description: e.target.value })}
                        className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-xs rounded p-1 text-slate-750 dark:text-slate-300 resize-none h-14"
                        placeholder="Description"
                      />
                      <textarea
                        value={t.mitigation}
                        onChange={(e) => updateThreat(t.threat_id, { mitigation: e.target.value })}
                        className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-xs rounded p-1 text-slate-750 dark:text-slate-300 resize-none h-14"
                        placeholder="Mitigation"
                      />

                      {/* CVSS Metrics Editor */}
                      <div className="border-t border-slate-200 dark:border-border pt-2 mt-2 space-y-2">
                        <span className="text-[9px] font-bold uppercase tracking-wider text-slate-500 block">CVSS Metrics Editor</span>
                        <div className="grid grid-cols-2 gap-1.5 text-[10px]">
                          <div>
                            <label className="block text-[8px] uppercase font-bold text-slate-455 mb-0.5">Attack Vector (AV)</label>
                            <select
                              value={parseCVSSVector(t.cvss_vector).AV}
                              onChange={(e) => {
                                const m = parseCVSSVector(t.cvss_vector);
                                m.AV = e.target.value as any;
                                const vec = generateCVSSVector(m);
                                const score = calculateCVSSBaseScore(m);
                                updateThreat(t.threat_id, { cvss_vector: vec, cvss_score: score });
                              }}
                              className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-0.5 rounded text-[10px] text-slate-800 dark:text-white"
                            >
                              <option value="N">Network (N)</option>
                              <option value="A">Adjacent (A)</option>
                              <option value="L">Local (L)</option>
                              <option value="P">Physical (P)</option>
                            </select>
                          </div>
                          <div>
                            <label className="block text-[8px] uppercase font-bold text-slate-455 mb-0.5">Complexity (AC)</label>
                            <select
                              value={parseCVSSVector(t.cvss_vector).AC}
                              onChange={(e) => {
                                const m = parseCVSSVector(t.cvss_vector);
                                m.AC = e.target.value as any;
                                const vec = generateCVSSVector(m);
                                const score = calculateCVSSBaseScore(m);
                                updateThreat(t.threat_id, { cvss_vector: vec, cvss_score: score });
                              }}
                              className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-0.5 rounded text-[10px] text-slate-800 dark:text-white"
                            >
                              <option value="L">Low (L)</option>
                              <option value="H">High (H)</option>
                            </select>
                          </div>
                          <div>
                            <label className="block text-[8px] uppercase font-bold text-slate-455 mb-0.5">Privileges (PR)</label>
                            <select
                              value={parseCVSSVector(t.cvss_vector).PR}
                              onChange={(e) => {
                                const m = parseCVSSVector(t.cvss_vector);
                                m.PR = e.target.value as any;
                                const vec = generateCVSSVector(m);
                                const score = calculateCVSSBaseScore(m);
                                updateThreat(t.threat_id, { cvss_vector: vec, cvss_score: score });
                              }}
                              className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-0.5 rounded text-[10px] text-slate-800 dark:text-white"
                            >
                              <option value="N">None (N)</option>
                              <option value="L">Low (L)</option>
                              <option value="H">High (H)</option>
                            </select>
                          </div>
                          <div>
                            <label className="block text-[8px] uppercase font-bold text-slate-455 mb-0.5">Interaction (UI)</label>
                            <select
                              value={parseCVSSVector(t.cvss_vector).UI}
                              onChange={(e) => {
                                const m = parseCVSSVector(t.cvss_vector);
                                m.UI = e.target.value as any;
                                const vec = generateCVSSVector(m);
                                const score = calculateCVSSBaseScore(m);
                                updateThreat(t.threat_id, { cvss_vector: vec, cvss_score: score });
                              }}
                              className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-0.5 rounded text-[10px] text-slate-800 dark:text-white"
                            >
                              <option value="N">None (N)</option>
                              <option value="R">Required (R)</option>
                            </select>
                          </div>
                          <div>
                            <label className="block text-[8px] uppercase font-bold text-slate-455 mb-0.5">Scope (S)</label>
                            <select
                              value={parseCVSSVector(t.cvss_vector).S}
                              onChange={(e) => {
                                const m = parseCVSSVector(t.cvss_vector);
                                m.S = e.target.value as any;
                                const vec = generateCVSSVector(m);
                                const score = calculateCVSSBaseScore(m);
                                updateThreat(t.threat_id, { cvss_vector: vec, cvss_score: score });
                              }}
                              className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-0.5 rounded text-[10px] text-slate-800 dark:text-white"
                            >
                              <option value="U">Unchanged (U)</option>
                              <option value="C">Changed (C)</option>
                            </select>
                          </div>
                          <div>
                            <label className="block text-[8px] uppercase font-bold text-slate-455 mb-0.5">Confidentiality (C)</label>
                            <select
                              value={parseCVSSVector(t.cvss_vector).C}
                              onChange={(e) => {
                                const m = parseCVSSVector(t.cvss_vector);
                                m.C = e.target.value as any;
                                const vec = generateCVSSVector(m);
                                const score = calculateCVSSBaseScore(m);
                                updateThreat(t.threat_id, { cvss_vector: vec, cvss_score: score });
                              }}
                              className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-0.5 rounded text-[10px] text-slate-800 dark:text-white"
                            >
                              <option value="N">None (N)</option>
                              <option value="L">Low (L)</option>
                              <option value="H">High (H)</option>
                            </select>
                          </div>
                          <div>
                            <label className="block text-[8px] uppercase font-bold text-slate-455 mb-0.5">Integrity (I)</label>
                            <select
                              value={parseCVSSVector(t.cvss_vector).I}
                              onChange={(e) => {
                                const m = parseCVSSVector(t.cvss_vector);
                                m.I = e.target.value as any;
                                const vec = generateCVSSVector(m);
                                const score = calculateCVSSBaseScore(m);
                                updateThreat(t.threat_id, { cvss_vector: vec, cvss_score: score });
                              }}
                              className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-0.5 rounded text-[10px] text-slate-800 dark:text-white"
                            >
                              <option value="N">None (N)</option>
                              <option value="L">Low (L)</option>
                              <option value="H">High (H)</option>
                            </select>
                          </div>
                          <div>
                            <label className="block text-[8px] uppercase font-bold text-slate-455 mb-0.5">Availability (A)</label>
                            <select
                              value={parseCVSSVector(t.cvss_vector).A}
                              onChange={(e) => {
                                const m = parseCVSSVector(t.cvss_vector);
                                m.A = e.target.value as any;
                                const vec = generateCVSSVector(m);
                                const score = calculateCVSSBaseScore(m);
                                updateThreat(t.threat_id, { cvss_vector: vec, cvss_score: score });
                              }}
                              className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border p-0.5 rounded text-[10px] text-slate-800 dark:text-white"
                            >
                              <option value="N">None (N)</option>
                              <option value="L">Low (L)</option>
                              <option value="H">High (H)</option>
                            </select>
                          </div>
                        </div>
                        <div className="text-[8px] font-mono bg-slate-100 dark:bg-slate-950 p-1.5 rounded select-all break-all leading-normal text-slate-500 mt-1">
                          Vector: {t.cvss_vector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <>
                      <h5 className="text-xs font-bold text-slate-950 dark:text-white leading-snug">
                        {t.title}
                      </h5>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal">
                        {t.description}
                      </p>
                      
                      {t.mitigation && (
                        <div className="mt-1 border-t border-slate-200 dark:border-border/50 pt-1.5">
                          <span className="text-[9px] font-bold uppercase tracking-wider text-emerald-500">Mitigation</span>
                          <p className="text-[10px] text-slate-500 dark:text-slate-400 leading-normal italic mt-0.5">
                            {t.mitigation}
                          </p>
                        </div>
                      )}
                    </>
                  )}

                  {t.reasoning && !isEditing && (
                    <div className="mt-2 border-t border-slate-200 dark:border-border/50 pt-2 bg-slate-100/50 dark:bg-slate-950/40 p-2.5 rounded text-[10px] leading-relaxed max-h-56 overflow-y-auto">
                      <span className="text-[8px] font-bold uppercase tracking-wider text-primary-500 block mb-1">Technical Reasoning (XAI)</span>
                      {renderReasoning(t.reasoning)}
                    </div>
                  )}

                  {linkedVulns.length > 0 && (
                    <div className="mt-2 border-t border-slate-200 dark:border-border/50 pt-2 space-y-1.5">
                      <span className="text-[9px] font-bold uppercase tracking-wider text-red-400">Vulnerabilities</span>
                      {linkedVulns.map(v => {
                        const isVulnEditing = editingVulnId === v.vulnerability_id;
                        const isVulnGenerating = generatingReasoningId === v.vulnerability_id;

                        return (
                          <div key={v.vulnerability_id} className="bg-white dark:bg-slate-950 border border-slate-100 dark:border-border/30 p-2 rounded text-[10px] flex flex-col gap-1 relative group/vuln">
                            
                            <div className="absolute top-1 right-1 flex items-center gap-1 opacity-0 group-hover/vuln:opacity-100 transition">
                              <button
                                onClick={() => generateReasoning(undefined, v.vulnerability_id)}
                                disabled={isVulnGenerating}
                                className="text-slate-400 hover:text-emerald-500 transition disabled:opacity-50"
                                title="Generate XAI reasoning"
                              >
                                <Sparkles className={`w-3 h-3 ${isVulnGenerating ? 'animate-pulse text-emerald-500' : ''}`} />
                              </button>
                              <button
                                onClick={() => setEditingVulnId(isVulnEditing ? null : v.vulnerability_id)}
                                className="text-slate-400 hover:text-primary-500 transition"
                                title="Edit Vulnerability"
                              >
                                <Edit className="w-3 h-3" />
                              </button>
                              <button
                                onClick={() => { if (confirm('Delete vulnerability?')) deleteVulnerability(v.vulnerability_id); }}
                                className="text-slate-400 hover:text-red-450 transition"
                                title="Delete Vulnerability"
                              >
                                <Trash2 className="w-3 h-3" />
                              </button>
                            </div>

                            {isVulnEditing ? (
                              <div className="space-y-1.5 mt-1 pr-12">
                                <input
                                  type="text"
                                  value={v.title}
                                  onChange={(e) => updateVulnerability(v.vulnerability_id, { title: e.target.value })}
                                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border text-[10px] rounded p-0.5 text-slate-800 dark:text-white"
                                />
                                <textarea
                                  value={v.description}
                                  onChange={(e) => updateVulnerability(v.vulnerability_id, { description: e.target.value })}
                                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border text-[10px] rounded p-0.5 text-slate-750 dark:text-slate-300 resize-none h-10"
                                />
                                <textarea
                                  value={v.mitigation}
                                  onChange={(e) => updateVulnerability(v.vulnerability_id, { mitigation: e.target.value })}
                                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border text-[10px] rounded p-0.5 text-slate-750 dark:text-slate-300 resize-none h-10"
                                />
                                <select
                                  value={v.status}
                                  onChange={(e) => updateVulnerability(v.vulnerability_id, { status: e.target.value })}
                                  className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border text-[9px] text-slate-800 dark:text-white rounded p-0.5"
                                >
                                  <option value="Open">Open</option>
                                  <option value="Mitigated">Mitigated</option>
                                </select>
                              </div>
                            ) : (
                              <>
                                <div className="flex justify-between items-center pr-12">
                                  <span className="font-semibold text-slate-800 dark:text-text">{v.title}</span>
                                  <span className="text-[8px] px-1 bg-red-500/10 text-red-500 font-bold uppercase rounded">{v.status}</span>
                                </div>
                                <p className="text-slate-500 dark:text-slate-400 leading-normal">{v.description}</p>
                                {v.mitigation && (
                                  <p className="text-[9px] text-slate-400 leading-normal mt-0.5"><span className="font-semibold text-emerald-500">Mitigation:</span> {v.mitigation}</p>
                                )}
                                {v.reasoning && (
                                  <div className="mt-2 border-t border-slate-100 dark:border-border/30 pt-2 bg-slate-50 dark:bg-slate-950/50 p-2 rounded text-[10px] leading-relaxed max-h-40 overflow-y-auto">
                                    <span className="text-[8px] font-bold uppercase tracking-wider text-primary-500 block mb-1">Reasoning</span>
                                    {renderReasoning(v.reasoning)}
                                  </div>
                                )}
                              </>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  // Find currently selected element
  const getSelectedElement = () => {
    if (!selectedElementId) return null;
    if (selectedElementType === 'component' || selectedElementType === 'boundary') {
      return nodes.find((n) => n.id === selectedElementId);
    }
    if (selectedElementType === 'flow') {
      return edges.find((e) => e.id === selectedElementId);
    }
    return null;
  };

  const element = getSelectedElement();
  const boundaries = nodes.filter((n) => n.type === 'boundaryNode');

  // Handle Multi-Selection view
  if (isMultiSelection) {
    return (
      <div style={{ width: `${sidebarWidth}px` }} className="relative border-l border-slate-200 dark:border-border bg-white dark:bg-card p-6 overflow-y-auto shrink-0 flex flex-col gap-5 select-text">
        <div
          onMouseDown={startResize}
          className="absolute left-0 top-0 bottom-0 w-1 cursor-col-resize hover:bg-primary-500/50 active:bg-primary-600 transition-colors z-50"
        />
        <div className="flex justify-between items-center border-b border-border pb-3">
          <h3 className="text-sm font-bold text-text uppercase tracking-wider flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4 text-amber-500" />
            Batch Selection
          </h3>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          Showing threats, mitigations, and vulnerabilities for all {selectedNodes.length} selected elements and {selectedEdges.length} flows.
        </p>
        {renderThreatsSection()}
      </div>
    );
  }

  // Handle asset management when nothing is selected
  if (!element || !selectedElementType) {
    return (
      <div style={{ width: `${sidebarWidth}px` }} className="relative border-l border-slate-200 dark:border-border bg-white dark:bg-card p-6 overflow-y-auto select-text shrink-0 flex flex-col gap-6">
        <div
          onMouseDown={startResize}
          className="absolute left-0 top-0 bottom-0 w-1 cursor-col-resize hover:bg-primary-500/50 active:bg-primary-600 transition-colors z-50"
        />
        <div>
          <h3 className="text-sm font-bold text-text uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <KeyRound className="w-4 h-4 text-primary-500" />
            Asset Ledger
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed mb-4">
            Create and edit security assets carried across data flows.
          </p>
          <button
            onClick={() => addAsset('New Asset')}
            className="w-full py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs font-semibold text-slate-700 dark:text-text hover:bg-slate-100 dark:hover:bg-slate-800 transition flex items-center justify-center gap-1"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Asset
          </button>
        </div>

        <div className="flex-1 flex flex-col gap-3">
          {assets.length === 0 ? (
            <div className="text-center py-8 text-xs text-slate-500 border border-dashed border-border rounded-lg">
              No assets in project.
            </div>
          ) : (
            assets.map((asset) => (
              <div
                key={asset.asset_id}
                className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border p-3 rounded-lg flex flex-col gap-2 relative group"
              >
                <button
                  onClick={() => deleteElement(asset.asset_id, 'asset')}
                  className="absolute top-2 right-2 text-slate-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
                <input
                  type="text"
                  value={asset.name}
                  onChange={(e) => updateAsset(asset.asset_id, { name: e.target.value })}
                  className="bg-transparent border-b border-transparent hover:border-slate-300 dark:hover:border-slate-700 focus:border-primary-500 text-xs font-semibold text-slate-800 dark:text-text focus:outline-none pr-6"
                />
                <div className="flex gap-2">
                  <select
                    value={asset.type}
                    onChange={(e) => updateAsset(asset.asset_id, { type: e.target.value as any })}
                    className="flex-1 bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-[10px] text-slate-700 dark:text-slate-300 rounded p-1"
                  >
                    <option value="Informational">Informational</option>
                    <option value="Physical">Physical</option>
                    <option value="None">None</option>
                  </select>
                  <select
                    value={asset.criticality}
                    onChange={(e) => updateAsset(asset.asset_id, { criticality: e.target.value as any })}
                    className="flex-1 bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-[10px] text-slate-700 dark:text-slate-300 rounded p-1"
                  >
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
                <textarea
                  placeholder="Asset description..."
                  value={asset.description}
                  onChange={(e) => updateAsset(asset.asset_id, { description: e.target.value })}
                  className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border text-[10px] text-slate-650 dark:text-slate-400 rounded p-1 focus:outline-none resize-none h-12"
                />
              </div>
            ))
          )}
        </div>
      </div>
    );
  }

  // ----------------------------------------------------
  // PROPERTIES PANEL FOR COMPONENT
  // ----------------------------------------------------
  if (selectedElementType === 'component') {
    const data = element.data;
    return (
      <div style={{ width: `${sidebarWidth}px` }} className="relative border-l border-slate-200 dark:border-border bg-white dark:bg-card p-6 overflow-y-auto shrink-0 flex flex-col gap-5 select-text">
        <div
          onMouseDown={startResize}
          className="absolute left-0 top-0 bottom-0 w-1 cursor-col-resize hover:bg-primary-500/50 active:bg-primary-600 transition-colors z-50"
        />
        <div className="flex justify-between items-center border-b border-border pb-3">
          <h3 className="text-sm font-bold text-text uppercase tracking-wider flex items-center gap-1.5">
            <Globe className="w-4 h-4 text-emerald-500" />
            Component Settings
          </h3>
          <button
            onClick={() => deleteElement(element.id, 'component')}
            className="text-slate-500 hover:text-red-400 transition"
            title="Delete Component"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>

        {/* Name */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Name</label>
          <input
            type="text"
            value={data.name}
            onChange={(e) => updateComponent(element.id, { name: e.target.value })}
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-text focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Component Type (Dynamic Input with Smart Defaults) */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Component Type</label>
          <input
            type="text"
            value={data.type}
            onChange={(e) => {
              const val = e.target.value;
              let inferredElement: 'Process' | 'Data Store' | 'Entity' = data.element_type;
              
              // Smart Defaults Inference Logic
              if (/db|database|sql|redis|vault|store|storage/i.test(val)) {
                inferredElement = 'Data Store';
              } else if (/api|service|server|logic|auth|backend/i.test(val)) {
                inferredElement = 'Process';
              } else if (/user|admin|surgeon|client|browser/i.test(val)) {
                inferredElement = 'Entity';
              }

              updateComponent(element.id, { type: val, element_type: inferredElement });
            }}
            placeholder="e.g. SQL Database, REST API"
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-text focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Element Type */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Element Type</label>
          <select
            value={data.element_type}
            onChange={(e) => updateComponent(element.id, { element_type: e.target.value as any })}
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-text focus:outline-none focus:border-primary-500"
          >
            <option value="Process">Process</option>
            <option value="Data Store">Data Store</option>
            <option value="Entity">Entity</option>
          </select>
        </div>

        {/* Trust Boundary */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Trust Boundary</label>
          <select
            value={data.trust_boundary_id || ''}
            onChange={(e) => updateComponent(element.id, { trust_boundary_id: e.target.value || null })}
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-text focus:outline-none focus:border-primary-500"
          >
            <option value="">None (Outside Any Boundary)</option>
            {boundaries.map((b) => (
              <option key={b.id} value={b.id}>
                {b.data.name}
              </option>
            ))}
          </select>
        </div>

        {/* Description */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Description</label>
          <textarea
            value={data.description}
            onChange={(e) => updateComponent(element.id, { description: e.target.value })}
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-700 dark:text-slate-300 focus:outline-none focus:border-primary-500 resize-none h-20"
          />
        </div>

        {/* Out of Scope Flag */}
        <div className="border-t border-slate-200 dark:border-border pt-4 flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-600 dark:text-slate-300">Out of Scope</span>
            <input
              type="checkbox"
              checked={data.is_out_of_scope}
              onChange={(e) => updateComponent(element.id, { is_out_of_scope: e.target.checked })}
              className="w-4 h-4 accent-primary-500 cursor-pointer"
            />
          </div>

          {data.is_out_of_scope && (
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Justification</label>
              <textarea
                value={data.out_of_scope_justification}
                onChange={(e) => updateComponent(element.id, { out_of_scope_justification: e.target.value })}
                placeholder="Required threat exclusion details..."
                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-700 dark:text-slate-300 focus:outline-none focus:border-primary-500 h-16"
              />
            </div>
          )}
        </div>
        {renderThreatsSection()}
      </div>
    );
  }

  // ----------------------------------------------------
  // PROPERTIES PANEL FOR BOUNDARY
  // ----------------------------------------------------
  if (selectedElementType === 'boundary') {
    const data = element.data;
    return (
      <div style={{ width: `${sidebarWidth}px` }} className="relative border-l border-slate-200 dark:border-border bg-white dark:bg-card p-6 overflow-y-auto shrink-0 flex flex-col gap-5 select-text">
        <div
          onMouseDown={startResize}
          className="absolute left-0 top-0 bottom-0 w-1 cursor-col-resize hover:bg-primary-500/50 active:bg-primary-600 transition-colors z-50"
        />
        <div className="flex justify-between items-center border-b border-border pb-3">
          <h3 className="text-sm font-bold text-text uppercase tracking-wider flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4 text-red-500" />
            Boundary Settings
          </h3>
          <button
            onClick={() => deleteElement(element.id, 'boundary')}
            className="text-slate-500 hover:text-red-400 transition"
            title="Delete Boundary"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>

        {/* Name */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Name</label>
          <input
            type="text"
            value={data.name}
            onChange={(e) => updateBoundary(element.id, { name: e.target.value })}
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-text focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Boundary Type */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Boundary Type</label>
          <input
            type="text"
            value={data.type}
            onChange={(e) => updateBoundary(element.id, { type: e.target.value })}
            placeholder="e.g. AWS VPC, Internal Network"
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-text focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Parent Boundary */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Parent Boundary</label>
          <select
            value={data.parent_boundary_id || ''}
            onChange={(e) => updateBoundary(element.id, { parent_boundary_id: e.target.value || null })}
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-text focus:outline-none focus:border-primary-500"
          >
            <option value="">None (Top Level)</option>
            {boundaries
              .filter((b) => b.id !== element.id)
              .map((b) => (
                <option key={b.id} value={b.id}>
                  {b.data.name}
                </option>
              ))}
          </select>
        </div>

        {/* Description */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Description</label>
          <textarea
            value={data.description}
            onChange={(e) => updateBoundary(element.id, { description: e.target.value })}
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-750 dark:text-slate-300 focus:outline-none focus:border-primary-500 resize-none h-20"
          />
        </div>
        {renderThreatsSection()}
      </div>
    );
  }

  // ----------------------------------------------------
  // PROPERTIES PANEL FOR DATA FLOWS
  // ----------------------------------------------------
  if (selectedElementType === 'flow') {
    const data = element.data;
    const carriedAssets = data.assets || [];

    const toggleAsset = (assetId: string) => {
      const updated = carriedAssets.includes(assetId)
        ? carriedAssets.filter((id: string) => id !== assetId)
        : [...carriedAssets, assetId];
      updateFlow(element.id, { assets: updated });
    };

    return (
      <div style={{ width: `${sidebarWidth}px` }} className="relative border-l border-slate-200 dark:border-border bg-white dark:bg-card p-6 overflow-y-auto shrink-0 flex flex-col gap-5 select-text">
        <div
          onMouseDown={startResize}
          className="absolute left-0 top-0 bottom-0 w-1 cursor-col-resize hover:bg-primary-500/50 active:bg-primary-600 transition-colors z-50"
        />
        <div className="flex justify-between items-center border-b border-slate-200 dark:border-border pb-3">
          <h3 className="text-sm font-bold text-text uppercase tracking-wider flex items-center gap-1.5">
            <FileText className="w-4 h-4 text-blue-500" />
            Data Flow Settings
          </h3>
          <button
            onClick={() => deleteElement(element.id, 'flow')}
            className="text-slate-500 hover:text-red-400 transition"
            title="Delete Flow"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>

        {/* Name / Action */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Flow Name</label>
          <input
            type="text"
            value={data.name}
            onChange={(e) => updateFlow(element.id, { name: e.target.value })}
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-text focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Protocol */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Protocol</label>
          <input
            type="text"
            value={data.protocol}
            onChange={(e) => updateFlow(element.id, { protocol: e.target.value })}
            placeholder="e.g. HTTPS, gRPC, JDBC"
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-text focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Authentication */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Authentication</label>
          <input
            type="text"
            value={data.authentication}
            onChange={(e) => updateFlow(element.id, { authentication: e.target.value })}
            placeholder="e.g. JWT, OAuth2, None"
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-text focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Encryption */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Encryption</label>
          <input
            type="text"
            value={data.encryption}
            onChange={(e) => updateFlow(element.id, { encryption: e.target.value })}
            placeholder="e.g. TLS 1.3, AES-256, None"
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-800 dark:text-text focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Directionality Toggle */}
        <div className="flex items-center justify-between border-t border-slate-200 dark:border-border pt-4">
          <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">Bidirectional Flow</span>
          <input
            type="checkbox"
            checked={data.is_bidirectional}
            onChange={(e) => updateFlow(element.id, { is_bidirectional: e.target.checked })}
            className="w-4 h-4 accent-primary-500 cursor-pointer"
          />
        </div>

        {/* Assets carried */}
        <div className="flex flex-col gap-2 border-t border-slate-200 dark:border-border pt-4">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Carried Assets</label>
          {assets.length === 0 ? (
            <span className="text-[10px] text-slate-500 italic">No assets defined. Add them in global ledger first.</span>
          ) : (
            <div className="flex flex-col gap-1.5 max-h-36 overflow-y-auto pr-1">
              {assets.map((a) => (
                <button
                  key={a.asset_id}
                  onClick={() => toggleAsset(a.asset_id)}
                  className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-left text-xs transition ${
                    carriedAssets.includes(a.asset_id)
                      ? 'bg-primary-50 dark:bg-primary-500/10 border-primary-200 dark:border-primary-500/30 text-primary-700 dark:text-primary-200'
                      : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-border text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                >
                  <CheckCircle2 className={`w-3.5 h-3.5 ${carriedAssets.includes(a.asset_id) ? 'text-primary-500 dark:text-primary-400' : 'text-slate-400 dark:text-slate-600'}`} />
                  <span className="truncate">{a.name}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Description */}
        <div className="flex flex-col gap-1.5 border-t border-slate-200 dark:border-border pt-4">
          <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Description</label>
          <textarea
            value={data.description}
            onChange={(e) => updateFlow(element.id, { description: e.target.value })}
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg text-xs p-2 text-slate-750 dark:text-slate-300 focus:outline-none focus:border-primary-500 resize-none h-16"
          />
        </div>
        {renderThreatsSection()}
      </div>
    );
  }

  return null;
}
