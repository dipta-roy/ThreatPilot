import { memo } from 'react';
import { Handle, Position, NodeProps, NodeResizer } from 'reactflow';
import { Server, Database, Box, ShieldAlert, EyeOff } from 'lucide-react';
import { useDesignerStore } from '../store/useDesignerStore';

// Custom Component Node
export const ComponentNode = memo(({ data, selected }: NodeProps) => {
  const isOutOfScope = data.is_out_of_scope;
  const elementType = data.element_type;
  const threats = useDesignerStore((state) => state.threats || []);
  const showRiskInCanvas = useDesignerStore((state) => state.showRiskInCanvas);

  const compName = (data.name || '').trim().toLowerCase();
  const componentThreatsCount = compName 
    ? threats.filter(t => (t.affected_components || '').toLowerCase().includes(compName)).length
    : 0;

  // Icon selector based on component element type
  const getIcon = () => {
    switch (elementType) {
      case 'Process':
        return <Server className="w-5 h-5 text-process" />;
      case 'Data Store':
        return <Database className="w-5 h-5 text-store" />;
      case 'Entity':
        return <Box className="w-5 h-5 text-entity" />;
      default:
        return <Server className="w-5 h-5 text-blue-400" />;
    }
  };

  const getTypeColor = () => {
    switch (elementType) {
      case 'Process':
        return 'border-emerald-500/40 bg-emerald-50 dark:bg-emerald-500/5 shadow-emerald-500/10';
      case 'Data Store':
        return 'border-amber-500/40 bg-amber-50 dark:bg-amber-500/5 shadow-amber-500/10';
      case 'Entity':
        return 'border-blue-500/40 bg-blue-50 dark:bg-blue-500/5 shadow-blue-500/10';
      default:
        return 'border-slate-300 dark:border-slate-500/40 bg-slate-50 dark:bg-slate-500/5';
    }
  };

  return (
    <div
      className={`group px-4 py-3 rounded-lg border-2 w-[140px] h-[90px] flex flex-col justify-between transition-all duration-200 shadow-lg ${
        isOutOfScope 
          ? 'border-dashed border-slate-600 bg-slate-800/40 opacity-60' 
          : getTypeColor()
      } ${selected ? 'ring-2 ring-primary-500 ring-offset-2 ring-offset-background scale-105' : ''}`}
    >
      {/* Handles (8 points: corners and sides) */}
      {[
        { id: 'top-left', pos: Position.Top, style: { left: '15%' } },
        { id: 'top', pos: Position.Top, style: { left: '50%' } },
        { id: 'top-right', pos: Position.Top, style: { left: '85%' } },
        { id: 'bottom-left', pos: Position.Bottom, style: { left: '15%' } },
        { id: 'bottom', pos: Position.Bottom, style: { left: '50%' } },
        { id: 'bottom-right', pos: Position.Bottom, style: { left: '85%' } },
        { id: 'left', pos: Position.Left, style: { top: '50%' } },
        { id: 'right', pos: Position.Right, style: { top: '50%' } },
      ].map((h) => (
        <Handle
          key={h.id}
          type="source"
          position={h.pos}
          id={h.id}
          style={{ ...h.style, zIndex: 11 }}
          className="opacity-0 group-hover:opacity-100 transition-opacity !bg-primary-500 !w-2.5 !h-2.5 !border-2 !border-white dark:!border-slate-800"
        />
      ))}

      <div className="flex items-center justify-between">
        <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500 dark:text-slate-400">
          {elementType}
        </span>
        <div className="flex items-center gap-1.5">
          {isOutOfScope && (
            <span title="Out of Scope">
              <EyeOff className="w-3.5 h-3.5 text-slate-400" />
            </span>
          )}
          {showRiskInCanvas && componentThreatsCount > 0 && (
            <span className="flex items-center justify-center bg-red-500 text-white text-[9px] font-extrabold w-4 h-4 rounded-full shadow-sm animate-pulse" title={`${componentThreatsCount} risks identified`}>
              {componentThreatsCount}
            </span>
          )}
          {getIcon()}
        </div>
      </div>

      {/* Body / Name */}
      <div className="mt-1 flex-1 flex items-center">
        <p className="text-xs font-bold text-slate-800 dark:text-text line-clamp-2 leading-snug">
          {data.name}
        </p>
      </div>

      {/* Footer / Subtype */}
      <div className="text-[9px] font-semibold text-slate-500 dark:text-slate-400 truncate">
        {data.type || 'Generic'}
      </div>

      {/* Source handles are now generated above with the target handles */}
    </div>
  );
});

// Custom Trust Boundary Container Node
export const BoundaryNode = memo(({ data, selected }: NodeProps) => {
  return (
    <div className="w-full h-full relative group">
      {/* NodeResizer component from React Flow handles boundary resizing */}
      <NodeResizer
        color="#0ea5e9"
        minWidth={150}
        minHeight={100}
        isVisible={selected}
        lineClassName="border-primary-500"
        handleClassName="w-3 h-3 bg-primary-500 border-2 border-background rounded-sm"
      />

      <div
        className={`w-full h-full rounded-xl border-2 border-dashed transition-all duration-200 flex flex-col justify-start p-3 ${
          selected
            ? 'border-primary-500 bg-primary-500/[0.03] dark:bg-primary-950/10 shadow-lg shadow-primary-500/5'
            : 'border-red-400/40 dark:border-red-500/30 bg-red-500/[0.01] dark:bg-red-950/5'
        }`}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-red-500/15 pb-1.5 mb-2 select-none">
          <div className="flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4 text-red-500/80" />
            <span className="text-xs font-bold text-red-800 dark:text-red-200/90 tracking-wide">
              {data.name}
            </span>
          </div>
          <span className="text-[9px] uppercase font-bold tracking-widest text-red-600/70 dark:text-red-400/60">
            {data.type || 'Boundary'}
          </span>
        </div>
        
        {/* Background watermark style element */}
        <div className="absolute inset-0 pointer-events-none flex items-center justify-center opacity-[0.02]">
          <ShieldAlert className="w-32 h-32 text-red-500" />
        </div>
      </div>
    </div>
  );
});
