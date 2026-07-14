import React, { useCallback, useRef, useEffect } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  BackgroundVariant,
  Node,
  Edge,
  ReactFlowInstance,
  ConnectionMode
} from 'reactflow';
import 'reactflow/dist/style.css';

import { useDesignerStore } from '../store/useDesignerStore';
import { ComponentNode, BoundaryNode } from './CustomNodes';
import { Loader2 } from 'lucide-react';

// Register custom node types
const nodeTypes = {
  componentNode: ComponentNode,
  boundaryNode: BoundaryNode,
};

export default function Canvas() {
  const {
    nodes,
    edges,
    onNodesChange,
    onEdgesChange,
    onConnect,
    selectElement,
    addComponent,
    addBoundary,
    undo,
    redo,
    deleteElement,
    selectedElementId,
    selectedElementType,
    isDarkMode,
    analyzingEdgeIds
  } = useDesignerStore();

  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  const [reactFlowInstance, setReactFlowInstance] = React.useState<ReactFlowInstance | null>(null);
  const [menu, setMenu] = React.useState<{ id: string, top: number, left: number } | null>(null);
  const [isGenerating, setIsGenerating] = React.useState(false);

  const onNodeContextMenu = useCallback((event: React.MouseEvent, node: Node) => {
    event.preventDefault();
    if (reactFlowWrapper.current) {
      const bounds = reactFlowWrapper.current.getBoundingClientRect();
      setMenu({ 
        id: node.id, 
        top: event.clientY - bounds.top, 
        left: event.clientX - bounds.left 
      });
    } else {
      setMenu({ id: node.id, top: event.clientY, left: event.clientX });
    }
  }, []);

  const handleRegenerateNodeThreats = async () => {
    if (!menu) return;
    const nodeId = menu.id;
    setMenu(null);
    setIsGenerating(true);
    window.dispatchEvent(new Event('start-ai-analysis'));
    try {
      const res = await fetch('/api/ai/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'STRIDE', iterations: 1, node_ids: [nodeId] })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(err.error || 'Failed to start node analysis');
      }
    } catch (e) {
      console.error(e);
      alert('Error connecting to backend');
    } finally {
      setIsGenerating(false);
    }
  };

  // Keyboard shortcut listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const activeTag = document.activeElement?.tagName.toLowerCase();
      if (activeTag === 'input' || activeTag === 'textarea' || activeTag === 'select') {
        return; // Don't interrupt text inputting
      }

      // Delete key
      if (e.key === 'Delete' || e.key === 'Backspace') {
        if (selectedElementId && selectedElementType) {
          deleteElement(selectedElementId, selectedElementType);
        }
      }

      // Ctrl + Z (Undo)
      if ((e.ctrlKey || e.metaKey) && e.key === 'z') {
        e.preventDefault();
        undo();
      }

      // Ctrl + Y (Redo)
      if ((e.ctrlKey || e.metaKey) && e.key === 'y') {
        e.preventDefault();
        redo();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedElementId, selectedElementType, undo, redo, deleteElement]);

  // Handle node selection click
  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    const type = node.type === 'boundaryNode' ? 'boundary' : 'component';
    selectElement(node.id, type);
  }, [selectElement]);

  // Handle edge selection click
  const onEdgeClick = useCallback((_: React.MouseEvent, edge: Edge) => {
    selectElement(edge.id, 'flow');
  }, [selectElement]);

  // Handle clicking on pane background (deselects)
  const onPaneClick = useCallback(() => {
    selectElement(null, null);
    setMenu(null);
  }, [selectElement]);

  // Drag and drop setup from side panel palette
  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();

      if (!reactFlowWrapper.current || !reactFlowInstance) return;

      const reactFlowBounds = reactFlowWrapper.current.getBoundingClientRect();
      const type = event.dataTransfer.getData('application/reactflow-type');
      const elementType = event.dataTransfer.getData('application/reactflow-elementtype');

      if (!type) return;

      const position = reactFlowInstance.project({
        x: event.clientX - reactFlowBounds.left - 60,
        y: event.clientY - reactFlowBounds.top - 45,
      });

      if (type === 'boundaryNode') {
        addBoundary('Trust Boundary', position.x, position.y);
      } else {
        addComponent(elementType as any, `New ${elementType}`, position.x, position.y);
      }
    },
    [reactFlowInstance, addComponent, addBoundary]
  );

  return (
    <div className="w-full h-full flex flex-col bg-slate-50 dark:bg-background" onClick={() => setMenu(null)}>
      {/* Top action bar */}
      <div className="h-14 bg-white dark:bg-card border-b border-slate-200 dark:border-border flex items-center justify-between px-6 select-none shrink-0 z-10">
        <div className="flex items-center gap-3">
          <div className="flex bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-border p-0.5 rounded-lg">
            <button
              onClick={() => addComponent('Process', 'Web Service', 250, 200)}
              className="px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-text hover:bg-slate-200 dark:hover:bg-slate-800 rounded-md transition"
            >
              + Process
            </button>
            <button
              onClick={() => addComponent('Data Store', 'Database', 250, 200)}
              className="px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-text hover:bg-slate-200 dark:hover:bg-slate-800 rounded-md transition"
            >
              + Data Store
            </button>
            <button
              onClick={() => addComponent('Entity', 'User', 250, 200)}
              className="px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-text hover:bg-slate-200 dark:hover:bg-slate-800 rounded-md transition"
            >
              + Entity
            </button>
            <button
              onClick={() => addBoundary('Trust Boundary', 200, 150)}
              className="px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-text hover:bg-slate-200 dark:hover:bg-slate-800 rounded-md transition"
            >
              + Boundary
            </button>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={undo}
            className="px-3 py-1.5 text-xs font-semibold bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300"
            title="Ctrl+Z"
          >
            Undo
          </button>
          <button
            onClick={redo}
            className="px-3 py-1.5 text-xs font-semibold bg-white dark:bg-slate-900 border border-slate-200 dark:border-border rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300"
            title="Ctrl+Y"
          >
            Redo
          </button>
        </div>
      </div>

      {/* Canvas workspace wrapper */}
      <div className="flex-1 w-full relative" ref={reactFlowWrapper}>
        <ReactFlow
          nodes={nodes}
          edges={edges.map(e => {
            const isForward = analyzingEdgeIds?.includes(e.id);
            const isReverse = analyzingEdgeIds?.includes(e.id + '_reverse');
            if (isForward || isReverse) {
              return {
                ...e,
                style: { ...e.style, stroke: '#6366f1', strokeWidth: 4, filter: 'drop-shadow(0 0 5px rgba(99,102,241,0.8))' },
                animated: true,
                className: isReverse ? 'animate-reverse' : ''
              };
            }
            return e;
          })}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          onNodeClick={onNodeClick}
          onNodeContextMenu={onNodeContextMenu}
          onEdgeClick={onEdgeClick}
          onPaneClick={onPaneClick}
          onInit={setReactFlowInstance}
          onDrop={onDrop}
          onDragOver={onDragOver}
          connectionMode={ConnectionMode.Loose}
          snapToGrid={true}
          snapGrid={[10, 10]}
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color={isDarkMode ? "#334155" : "#cbd5e1"} />
          <Controls className="bg-white dark:bg-card border border-slate-200 dark:border-border text-slate-800 dark:text-slate-300" />
          <MiniMap nodeStrokeWidth={3} zoomable pannable />
        </ReactFlow>
        
        {menu && (
          <div
            style={{ top: menu.top, left: menu.left }}
            className="absolute z-50 min-w-48 bg-white dark:bg-slate-800 rounded-md shadow-lg border border-slate-200 dark:border-slate-700 py-1 overflow-hidden"
          >
            <button
              onClick={handleRegenerateNodeThreats}
              className="w-full text-left px-4 py-2 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition"
            >
              Generate AI Threats
            </button>
          </div>
        )}

        {isGenerating && (
          <div className="absolute top-4 left-1/2 transform -translate-x-1/2 z-50 bg-indigo-600 text-white px-4 py-2 rounded-full shadow-lg flex items-center gap-2 font-medium text-sm animate-fade-in">
            <Loader2 className="w-4 h-4 animate-spin" />
            Analyzing Threat Model...
          </div>
        )}
      </div>
    </div>
  );
}
