import React, { useState } from 'react';
import { X } from 'lucide-react';
import { useDesignerStore } from '../store/useDesignerStore';

interface AddMitigationModalProps {
  onClose: () => void;
}

export default function AddMitigationModal({ onClose }: AddMitigationModalProps) {
  const addMitigationRequirement = useDesignerStore((state) => state.addMitigationRequirement);
  const nodes = useDesignerStore((state) => state.nodes);

  const [formData, setFormData] = useState({
    title: '',
    short_description: '',
    mitigation: '',
    test_case: '',
  });
  const [selectedComponents, setSelectedComponents] = useState<string[]>([]);

  const componentNames = nodes
    .filter(n => n.type === 'componentNode')
    .map(n => n.data.name as string)
    .filter(Boolean);

  const toggleComponent = (comp: string) => {
    setSelectedComponents(prev => 
      prev.includes(comp) ? prev.filter(c => c !== comp) : [...prev, comp]
    );
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.title) return;
    addMitigationRequirement({
      ...formData,
      affected_components: selectedComponents.join(', '),
    });
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-white dark:bg-slate-900 rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col border border-slate-200 dark:border-border">
        
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-border">
          <h2 className="text-lg font-bold text-slate-800 dark:text-white">Add Mitigation Requirement</h2>
          <button onClick={onClose} className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition">
            <X className="w-5 h-5 text-slate-500" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 overflow-y-auto flex-1 space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Title</label>
            <input 
              type="text" 
              required
              value={formData.title}
              onChange={e => setFormData({ ...formData, title: e.target.value })}
              className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500"
              placeholder="e.g. Implement Input Validation"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Short Description</label>
            <input 
              type="text" 
              value={formData.short_description}
              onChange={e => setFormData({ ...formData, short_description: e.target.value })}
              className="w-full bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500"
              placeholder="e.g. Validate all user inputs against schema"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Mitigation Details</label>
            <textarea 
              value={formData.mitigation}
              onChange={e => setFormData({ ...formData, mitigation: e.target.value })}
              className="w-full h-20 bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500 resize-none"
              placeholder="Detailed mitigation strategy..."
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Test Case</label>
            <textarea 
              value={formData.test_case}
              onChange={e => setFormData({ ...formData, test_case: e.target.value })}
              className="w-full h-20 bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-border rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-primary-500 resize-none"
              placeholder="Describe how to test if this mitigation is effective..."
            />
          </div>

          <div>
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

          <div className="mt-4 flex justify-end gap-3 pt-4 border-t border-slate-200 dark:border-border">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm font-semibold text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition">Cancel</button>
            <button type="submit" className="px-4 py-2 text-sm font-semibold text-white bg-primary-600 hover:bg-primary-500 rounded-lg transition shadow-md">Add Mitigation</button>
          </div>
        </form>
      </div>
    </div>
  );
}
