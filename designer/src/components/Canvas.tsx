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
    isDarkMode
  } = useDesignerStore();

  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  const [reactFlowInstance, setReactFlowInstance] = React.useState<ReactFlowInstance | null>(null);

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
    <div className="w-full h-full flex flex-col bg-slate-50 dark:bg-background">
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
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          onNodeClick={onNodeClick}
          onEdgeClick={onEdgeClick}
          onPaneClick={onPaneClick}
          onInit={setReactFlowInstance}
          onDrop={onDrop}
          onDragOver={onDragOver}
          connectionMode={ConnectionMode.Loose}
          snapToGrid={true}
          snapGrid={[10, 10]}
          fitView
          attributionPosition="bottom-right"
        >
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color={isDarkMode ? "#334155" : "#cbd5e1"} />
          <Controls className="bg-white dark:bg-card border border-slate-200 dark:border-border text-slate-800 dark:text-slate-300" />
          <MiniMap nodeStrokeWidth={3} zoomable pannable />
        </ReactFlow>
      </div>
    </div>
  );
}
