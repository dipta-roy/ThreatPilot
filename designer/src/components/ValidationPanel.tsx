
import { useDesignerStore } from '../store/useDesignerStore';
import { AlertTriangle, ShieldCheck } from 'lucide-react';

interface WarningItem {
  id: string;
  type: 'component' | 'boundary' | 'flow' | 'general';
  message: string;
}

export default function ValidationPanel() {
  const { nodes, edges } = useDesignerStore();

  const getWarnings = (): WarningItem[] => {
    const warnings: WarningItem[] = [];
    const components = nodes.filter((n) => n.type === 'componentNode');
    const boundaries = nodes.filter((n) => n.type === 'boundaryNode');

    // 1. Duplicate component names
    const componentNames = components.map((c) => c.data.name.trim().toLowerCase());
    const duplicateNames = componentNames.filter((item, index) => componentNames.indexOf(item) !== index);
    if (duplicateNames.length > 0) {
      duplicateNames.forEach((name) => {
        warnings.push({
          id: `dup-comp-${name}`,
          type: 'component',
          message: `Duplicate component name detected: "${name}". Ensure component names are unique.`,
        });
      });
    }

    // 2. Duplicate boundaries
    const boundaryNames = boundaries.map((b) => b.data.name.trim().toLowerCase());
    const duplicateBoundaries = boundaryNames.filter((item, index) => boundaryNames.indexOf(item) !== index);
    if (duplicateBoundaries.length > 0) {
      duplicateBoundaries.forEach((name) => {
        warnings.push({
          id: `dup-bound-${name}`,
          type: 'boundary',
          message: `Duplicate boundary name detected: "${name}".`,
        });
      });
    }

    // 3. Flow validation (without protocol or self-references)
    edges.forEach((e) => {
      const sourceNode = components.find((n) => n.id === e.source);
      const targetNode = components.find((n) => n.id === e.target);

      if (!sourceNode || !targetNode) {
        warnings.push({
          id: `flow-orphan-${e.id}`,
          type: 'flow',
          message: `Orphaned flow: connection is missing a valid source or target component.`,
        });
      }

      if (e.source === e.target) {
        warnings.push({
          id: `flow-self-${e.id}`,
          type: 'flow',
          message: `Circular self-reference: Flow "${e.data.name || 'Data Flow'}" connects a component to itself.`,
        });
      }

      if (!e.data.protocol || e.data.protocol.trim() === '') {
        warnings.push({
          id: `flow-proto-${e.id}`,
          type: 'flow',
          message: `Flow "${e.data.name || 'Data Flow'}" is missing a communication protocol (e.g. HTTPS).`,
        });
      }
    });

    // 4. Empty boundaries
    boundaries.forEach((b) => {
      const contained = components.filter((c) => c.data.trust_boundary_id === b.id);
      const containedSubBoundaries = boundaries.filter((sub) => sub.data.parent_boundary_id === b.id);
      
      if (contained.length === 0 && containedSubBoundaries.length === 0) {
        warnings.push({
          id: `empty-bound-${b.id}`,
          type: 'boundary',
          message: `Boundary "${b.data.name}" is empty and contains no components.`,
        });
      }
    });

    // 5. Component outside any boundary
    components.forEach((c) => {
      if (!c.data.trust_boundary_id) {
        warnings.push({
          id: `outside-bound-${c.id}`,
          type: 'component',
          message: `Component "${c.data.name}" lies outside of any defined trust boundary.`,
        });
      }
    });

    // 6. Disconnected components
    components.forEach((c) => {
      const connectedEdges = edges.filter((e) => e.source === c.id || e.target === c.id);
      if (connectedEdges.length === 0) {
        warnings.push({
          id: `disconnected-${c.id}`,
          type: 'component',
          message: `Component "${c.data.name}" is completely disconnected from the flow map.`,
        });
      }
    });

    // 7. Invalid nested boundaries (Circular references)
    boundaries.forEach((b) => {
      let currentParentId = b.data.parent_boundary_id;
      const visited = new Set<string>([b.id]);
      
      while (currentParentId) {
        if (visited.has(currentParentId)) {
          warnings.push({
            id: `circular-bound-${b.id}`,
            type: 'boundary',
            message: `Circular nested boundary loop detected starting at boundary "${b.data.name}".`,
          });
          break;
        }
        visited.add(currentParentId);
        const parent = boundaries.find((p) => p.id === currentParentId);
        currentParentId = parent ? parent.data.parent_boundary_id : null;
      }
    });

    return warnings;
  };

  const warnings = getWarnings();

  return (
    <div className="h-full flex flex-col select-none">
      <div className="p-4 border-b border-slate-200 dark:border-border shrink-0 flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-amber-500" />
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
          Validation Engine
        </h3>
        <span className="text-[10px] bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-border text-slate-500 dark:text-slate-400 font-bold px-1.5 py-0.5 rounded-full ml-auto">
          {warnings.length}
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
        {warnings.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 gap-3 text-center border border-dashed border-emerald-500/20 bg-emerald-500/5 dark:bg-emerald-950/5 rounded-xl p-4">
            <ShieldCheck className="w-10 h-10 text-emerald-600 dark:text-emerald-500/80" />
            <div>
              <p className="text-xs font-semibold text-emerald-800 dark:text-emerald-200">No architecture warnings</p>
              <p className="text-[10px] text-slate-500 mt-1 max-w-[200px]">
                Your system graph conforms cleanly to secure data flow layout principles.
              </p>
            </div>
          </div>
        ) : (
          warnings.map((w) => (
            <div
              key={w.id}
              className="bg-amber-50 dark:bg-slate-900/60 border border-amber-500/30 dark:border-amber-500/20 hover:border-amber-500/50 dark:hover:border-amber-500/40 p-3 rounded-lg flex items-start gap-2.5 transition"
            >
              <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-500 shrink-0 mt-0.5" />
              <p className="text-[11px] leading-relaxed text-slate-700 dark:text-slate-300">{w.message}</p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
