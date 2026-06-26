import { useDesignerStore } from '../store/useDesignerStore';
import { Trash2, Plus, ShieldAlert, KeyRound, Globe, FileText, CheckCircle2 } from 'lucide-react';

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
    deleteElement
  } = useDesignerStore();

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

  // Handle asset management when nothing is selected
  if (!element || !selectedElementType) {
    return (
      <div className="w-80 border-l border-slate-200 dark:border-border bg-white dark:bg-card p-6 overflow-y-auto select-none shrink-0 flex flex-col gap-6">
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
      <div className="w-80 border-l border-slate-200 dark:border-border bg-white dark:bg-card p-6 overflow-y-auto shrink-0 flex flex-col gap-5 select-none">
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
      </div>
    );
  }

  // ----------------------------------------------------
  // PROPERTIES PANEL FOR BOUNDARY
  // ----------------------------------------------------
  if (selectedElementType === 'boundary') {
    const data = element.data;
    return (
      <div className="w-80 border-l border-slate-200 dark:border-border bg-white dark:bg-card p-6 overflow-y-auto shrink-0 flex flex-col gap-5 select-none">
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
      <div className="w-80 border-l border-slate-200 dark:border-border bg-white dark:bg-card p-6 overflow-y-auto shrink-0 flex flex-col gap-5 select-none">
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
      </div>
    );
  }

  return null;
}
