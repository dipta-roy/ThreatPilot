import React, { useState } from 'react';
import { X } from 'lucide-react';
import { useDesignerStore, parseCVSSVector, generateCVSSVector, calculateCVSSBaseScore, CVSSMetrics } from '../store/useDesignerStore';

interface AddThreatModalProps {
  onClose: () => void;
}

export default function AddThreatModal({ onClose }: AddThreatModalProps) {
  const addThreat = useDesignerStore((state) => state.addThreat);
  const nodes = useDesignerStore((state) => state.nodes);

  const [formData, setFormData] = useState({
    title: '',
    category: '',
    description: '',
    impact: '',
    likelihood: 3,
    mitigation: '',
    is_accepted_risk: false,
    acceptance_justification: '',
    cvss_score: 0,
    mitre_attack_id: '',
    cvss_vector: '',
  });
  const [selectedComponents, setSelectedComponents] = useState<string[]>([]);
  const [cvssMetrics, setCvssMetrics] = useState<CVSSMetrics>(parseCVSSVector(''));
  const [isCvssSet, setIsCvssSet] = useState(false);

  const componentNames = nodes
    .filter(n => n.type === 'componentNode')
    .map(n => n.data.name as string)
    .filter(Boolean);

  const toggleComponent = (comp: string) => {
    setSelectedComponents(prev => 
      prev.includes(comp) ? prev.filter(c => c !== comp) : [...prev, comp]
    );
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
    if (!formData.title) return;
    addThreat({
      ...formData,
      affected_components: selectedComponents.join(', '),
      vulnerability_ids: [],
    });
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-white dark:bg-slate-900 rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col border border-slate-200 dark:border-border">
        
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-border">
          <h2 className="text-lg font-bold text-slate-800 dark:text-white">Add Threat</h2>
          <button onClick={onClose} className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition">
            <X className="w-5 h-5 text-slate-500" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 overflow-y-auto flex-1 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Title</label>
              <input 
                type="text" 
                required
                value={formData.title}
                onChange={e => setFormData({ ...formData, title: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500"
                placeholder="e.g. SQL Injection via Search Input"
              />
            </div>
            
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Category</label>
              <input 
                type="text" 
                value={formData.category}
                onChange={e => setFormData({ ...formData, category: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500"
                placeholder="e.g. Spoofing, Tampering"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">MITRE ATT&CK ID</label>
              <input 
                type="text" 
                value={formData.mitre_attack_id}
                onChange={e => setFormData({ ...formData, mitre_attack_id: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500"
                placeholder="e.g. T1190"
              />
            </div>
          </div>

          <div className="col-span-2">
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Description</label>
            <textarea 
              value={formData.description}
              onChange={e => setFormData({ ...formData, description: e.target.value })}
              className="w-full h-20 bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500 resize-none"
              placeholder="Detailed description of the threat..."
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Impact</label>
              <input 
                type="text" 
                value={formData.impact}
                onChange={e => setFormData({ ...formData, impact: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500"
                placeholder="High, Medium, Low, etc."
              />
            </div>
            
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Likelihood (1-5)</label>
              <input 
                type="number" 
                min="1" max="5"
                value={formData.likelihood}
                onChange={e => setFormData({ ...formData, likelihood: Number(e.target.value) })}
                className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500"
              />
            </div>
          </div>

          <div className="col-span-2 mt-2 p-3 bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg">
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

          <div className="col-span-2">
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">Affected Components</label>
            <div className="flex flex-wrap gap-2">
              {componentNames.map(comp => (
                <button
                  key={comp}
                  type="button"
                  onClick={() => toggleComponent(comp)}
                  className={`px-3 py-1 text-xs rounded-full border transition ${
                    selectedComponents.includes(comp)
                      ? 'bg-primary-500 text-white border-primary-600'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700'
                  }`}
                >
                  {comp}
                </button>
              ))}
            </div>
            {componentNames.length === 0 && <span className="text-xs text-slate-500">No components available in the canvas.</span>}
          </div>

          <div className="col-span-2 mt-4 flex justify-end gap-3 pt-4 border-t border-slate-200 dark:border-border">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm font-semibold text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition">Cancel</button>
            <button type="submit" className="px-4 py-2 text-sm font-semibold text-white bg-primary-600 hover:bg-primary-500 rounded-lg transition shadow-md">Add Threat</button>
          </div>
        </form>
      </div>
    </div>
  );
}
