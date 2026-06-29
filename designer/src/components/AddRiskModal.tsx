import React, { useState } from 'react';
import { X } from 'lucide-react';
import { useDesignerStore, parseCVSSVector, generateCVSSVector, calculateCVSSBaseScore, CVSSMetrics } from '../store/useDesignerStore';

interface AddRiskModalProps {
  onClose: () => void;
}

export default function AddRiskModal({ onClose }: AddRiskModalProps) {
  const addThreat = useDesignerStore((state) => state.addThreat);
  const nodes = useDesignerStore((state) => state.nodes);
  const vulnerabilities = useDesignerStore((state) => state.vulnerabilities);

  const [formData, setFormData] = useState({
    description: '',
    impact: '',
    likelihood: 3,
    cvss_vector: '',
    cvss_score: 0,
    mitigation: ''
  });
  
  const [selectedComponents, setSelectedComponents] = useState<string[]>([]);
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [selectedVulns, setSelectedVulns] = useState<string[]>([]);
  
  const [cvssMetrics, setCvssMetrics] = useState<CVSSMetrics>(parseCVSSVector(''));
  const [isCvssSet, setIsCvssSet] = useState(false);

  const componentNames = nodes
    .filter(n => n.type === 'componentNode')
    .map(n => n.data.name as string)
    .filter(Boolean);

  const toggleSelection = (item: string, list: string[], setList: (val: string[]) => void) => {
    setList(list.includes(item) ? list.filter(i => i !== item) : [...list, item]);
  };

  const handleCvssChange = (metric: keyof CVSSMetrics, value: string) => {
    const newMetrics = { ...cvssMetrics, [metric]: value as any };
    setCvssMetrics(newMetrics);
    setIsCvssSet(true);
    
    const vector = generateCVSSVector(newMetrics);
    const score = calculateCVSSBaseScore(newMetrics);
    
    setFormData(prev => ({
      ...prev,
      cvss_vector: vector,
      cvss_score: parseFloat(score.toFixed(1))
    }));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.description) return;
    
    // Title is the first sentence of description
    let derivedTitle = formData.description;
    const firstPeriodIdx = derivedTitle.indexOf('.');
    if (firstPeriodIdx !== -1) {
      derivedTitle = derivedTitle.substring(0, firstPeriodIdx).trim();
    }

    addThreat({
      title: derivedTitle,
      category: "Tampering", // Default category
      description: formData.description,
      impact: formData.impact,
      likelihood: formData.likelihood,
      mitigation: formData.mitigation,
      cvss_vector: formData.cvss_vector,
      cvss_score: formData.cvss_score,
      affected_components: selectedComponents.join(', '),
      affected_asset_type: selectedAssets.join(', '),
      vulnerability_ids: selectedVulns,
      is_accepted_risk: false,
      acceptance_justification: '',
      mitre_attack_id: ''
    });
    
    onClose();
  };

  const getSeverity = (score: number) => {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score > 0) return 'Low';
    return 'None';
  };

  return (
    <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-hidden flex flex-col">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-border flex justify-between items-center bg-slate-50 dark:bg-slate-950">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">Add New Risk</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition">
            <X className="w-4 h-4" />
          </button>
        </div>
        
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto">
          <div className="p-6 space-y-4">
            
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Elements (Components)</label>
                <div className="relative">
                  <div className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg p-2 max-h-32 overflow-y-auto">
                    {componentNames.length === 0 ? (
                      <div className="text-xs text-slate-400 italic">No components found</div>
                    ) : (
                      componentNames.map(comp => (
                        <label key={comp} className="flex items-center gap-2 p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded cursor-pointer">
                          <input 
                            type="checkbox" 
                            checked={selectedComponents.includes(comp)}
                            onChange={() => toggleSelection(comp, selectedComponents, setSelectedComponents)}
                            className="rounded border-slate-300 text-primary-600 focus:ring-primary-500"
                          />
                          <span className="text-xs text-slate-700 dark:text-slate-300">{comp}</span>
                        </label>
                      ))
                    )}
                  </div>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Assets</label>
                <div className="relative">
                  <div className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg p-2 max-h-32 overflow-y-auto">
                    {componentNames.length === 0 ? (
                      <div className="text-xs text-slate-400 italic">No components found</div>
                    ) : (
                      componentNames.map(comp => (
                        <label key={`asset-${comp}`} className="flex items-center gap-2 p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded cursor-pointer">
                          <input 
                            type="checkbox" 
                            checked={selectedAssets.includes(comp)}
                            onChange={() => toggleSelection(comp, selectedAssets, setSelectedAssets)}
                            className="rounded border-slate-300 text-primary-600 focus:ring-primary-500"
                          />
                          <span className="text-xs text-slate-700 dark:text-slate-300">{comp}</span>
                        </label>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Vulnerabilities</label>
              <div className="relative">
                <div className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg p-2 max-h-32 overflow-y-auto">
                  {vulnerabilities.length === 0 ? (
                    <div className="text-xs text-slate-400 italic">No vulnerabilities found</div>
                  ) : (
                    vulnerabilities.map(vuln => (
                      <label key={vuln.vulnerability_id} className="flex items-start gap-2 p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded cursor-pointer">
                        <input 
                          type="checkbox" 
                          checked={selectedVulns.includes(vuln.vulnerability_id)}
                          onChange={() => toggleSelection(vuln.vulnerability_id, selectedVulns, setSelectedVulns)}
                          className="rounded border-slate-300 text-primary-600 focus:ring-primary-500 mt-0.5"
                        />
                        <span className="text-xs text-slate-700 dark:text-slate-300">{vuln.title}</span>
                      </label>
                    ))
                  )}
                </div>
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Risk Description</label>
              <textarea 
                required
                rows={3}
                value={formData.description}
                onChange={e => setFormData({ ...formData, description: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500 resize-none"
                placeholder="The first sentence will be used as the title. Describe the risk in detail..."
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Impact</label>
              <textarea 
                rows={2}
                value={formData.impact}
                onChange={e => setFormData({ ...formData, impact: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500 resize-none"
                placeholder="Describe the impact if this risk occurs..."
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Likelihood (1-5)</label>
                <input 
                  type="number" 
                  min="1" max="5"
                  value={formData.likelihood}
                  onChange={e => setFormData({ ...formData, likelihood: Number(e.target.value) })}
                  className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Severity</label>
                <input 
                  type="text" 
                  readOnly
                  value={isCvssSet ? getSeverity(formData.cvss_score) : 'None'}
                  className="w-full bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-500 font-semibold focus:outline-none cursor-not-allowed"
                />
              </div>
            </div>

            <div className="p-3 bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg">
              <div className="flex justify-between items-center mb-3">
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300">CVSS v3.1 Metrics</label>
                <div className="text-xs font-mono text-slate-500">
                  {isCvssSet ? formData.cvss_vector : 'Not set'} 
                  {isCvssSet && <span className="ml-2 font-bold text-primary-600">Score: {formData.cvss_score}</span>}
                </div>
              </div>
              
              <div className="grid grid-cols-4 gap-3">
                <div>
                  <label className="block text-[10px] font-semibold text-slate-500 mb-1">Attack Vector (AV)</label>
                  <select value={cvssMetrics.AV} onChange={e => handleCvssChange('AV', e.target.value)} className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2 py-1 text-xs">
                    <option value="N">Network</option><option value="A">Adjacent</option><option value="L">Local</option><option value="P">Physical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] font-semibold text-slate-500 mb-1">Complexity (AC)</label>
                  <select value={cvssMetrics.AC} onChange={e => handleCvssChange('AC', e.target.value)} className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2 py-1 text-xs">
                    <option value="L">Low</option><option value="H">High</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] font-semibold text-slate-500 mb-1">Privileges (PR)</label>
                  <select value={cvssMetrics.PR} onChange={e => handleCvssChange('PR', e.target.value)} className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2 py-1 text-xs">
                    <option value="N">None</option><option value="L">Low</option><option value="H">High</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] font-semibold text-slate-500 mb-1">Interaction (UI)</label>
                  <select value={cvssMetrics.UI} onChange={e => handleCvssChange('UI', e.target.value)} className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2 py-1 text-xs">
                    <option value="N">None</option><option value="R">Required</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] font-semibold text-slate-500 mb-1">Scope (S)</label>
                  <select value={cvssMetrics.S} onChange={e => handleCvssChange('S', e.target.value)} className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2 py-1 text-xs">
                    <option value="U">Unchanged</option><option value="C">Changed</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] font-semibold text-slate-500 mb-1">Confidentiality (C)</label>
                  <select value={cvssMetrics.C} onChange={e => handleCvssChange('C', e.target.value)} className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2 py-1 text-xs">
                    <option value="N">None</option><option value="L">Low</option><option value="H">High</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] font-semibold text-slate-500 mb-1">Integrity (I)</label>
                  <select value={cvssMetrics.I} onChange={e => handleCvssChange('I', e.target.value)} className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2 py-1 text-xs">
                    <option value="N">None</option><option value="L">Low</option><option value="H">High</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] font-semibold text-slate-500 mb-1">Availability (A)</label>
                  <select value={cvssMetrics.A} onChange={e => handleCvssChange('A', e.target.value)} className="w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-border rounded px-2 py-1 text-xs">
                    <option value="N">None</option><option value="L">Low</option><option value="H">High</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-700 dark:text-slate-300">Mitigations</label>
              <textarea 
                rows={2}
                value={formData.mitigation}
                onChange={e => setFormData({ ...formData, mitigation: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500 resize-none"
                placeholder="Describe any mitigations or controls..."
              />
            </div>
            
          </div>
          <div className="px-6 py-4 border-t border-slate-200 dark:border-border bg-slate-50 dark:bg-slate-950 flex justify-end gap-3 mt-auto">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-slate-200 hover:bg-slate-300 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-semibold rounded-lg transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!formData.description}
              className="px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white text-xs font-semibold rounded-lg shadow-md transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Save Risk
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
