import React, { useEffect } from 'react';
import { useDesignerStore } from './store/useDesignerStore';
import Canvas from './components/Canvas';
import PropertiesPanel from './components/PropertiesPanel';
import ValidationPanel from './components/ValidationPanel';
import ExportOutputPanel from './components/ExportOutputPanel';
import { ShieldAlert, Save, RefreshCw, Layers, Sun, Moon } from 'lucide-react';

export default function App() {
  const {
    projectName,
    fetchProject,
    saveProject,
    hasUnsavedChanges,
    isSaving,
    saveError,
    isLoading,
    isDarkMode,
    toggleTheme
  } = useDesignerStore();

  // Load project on mount
  useEffect(() => {
    fetchProject();
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
            onClick={() => saveProject(false)}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-primary-600 hover:bg-primary-500 text-white text-xs font-semibold rounded-lg shadow-md transition disabled:opacity-50"
            disabled={isSaving}
          >
            <Save className="w-3.5 h-3.5" />
            Save Diagram
          </button>
        </div>
      </header>

      {/* Main Panel Body */}
      {isLoading ? (
        <div className="flex-1 w-full flex items-center justify-center flex-col gap-3">
          <RefreshCw className="w-8 h-8 text-primary-500 animate-spin" />
          <p className="text-xs text-slate-400 font-mono">Loading ThreatPilot Project Model...</p>
        </div>
      ) : (
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
    </div>
  );
}
