import { create } from 'zustand';
import { Node, Edge, Connection, addEdge, applyNodeChanges, applyEdgeChanges, NodeChange, EdgeChange, MarkerType } from 'reactflow';

export interface Asset {
  asset_id: string;
  name: string;
  type: 'Physical' | 'Informational' | 'None';
  description: string;
  criticality: 'High' | 'Medium' | 'Low';
  is_out_of_scope: boolean;
  out_of_scope_justification: string;
}

export interface Threat {
  threat_id: string;
  category: string;
  title: string;
  description: string;
  impact: string;
  likelihood: number;
  mitigation: string;
  is_accepted_risk: boolean;
  acceptance_justification: string;
  vulnerability_ids: string[];
  affected_components: string;
  cvss_score: number;
  mitre_attack_id: string;
  reasoning?: string;
  cvss_vector: string;
  cvss_rationale?: string;
  affected_asset_type?: string;
}

export interface Vulnerability {
  vulnerability_id: string;
  title: string;
  description: string;
  mitigation: string;
  status: string;
  reasoning?: string;
}

export interface MitigationRequirement {
  req_id: string;
  title: string;
  affected_components: string;
  mitigation: string;
  short_description: string;
  test_case: string;
  reasoning?: string;
}

export interface ComponentData {
  component_id: string;
  name: string;
  type: string;
  element_type: 'Process' | 'Data Store' | 'Entity' | 'None';
  asset_type: 'Physical' | 'Informational' | 'None';
  trust_boundary_id: string | null;
  description: string;
  is_out_of_scope: boolean;
  out_of_scope_justification: string;
}

export interface BoundaryData {
  boundary_id: string;
  name: string;
  type: string;
  description: string;
  parent_boundary_id: string | null;
}

export interface FlowData {
  flow_id: string;
  name: string;
  source_id: string;
  target_id: string;
  protocol: string;
  description: string;
  is_out_of_scope: boolean;
  out_of_scope_justification: boolean;
  is_bidirectional: boolean;
  trust_boundary_id: string | null;
  authentication: string;
  encryption: string;
  assets: string[]; // Asset IDs carried
}

interface ProjectMetadata {
  project_name: string;
  project_path: string;
  created_at: string;
  updated_at: string;
}

interface DesignerState {
  projectName: string;
  metadata: ProjectMetadata | null;
  nodes: Node[];
  edges: Edge[];
  assets: Asset[];
  customComponentTypes: string[];
  
  // Selection
  selectedElementId: string | null;
  selectedElementType: 'component' | 'boundary' | 'flow' | 'asset' | null;

  threats: Threat[];
  vulnerabilities: Vulnerability[];
  mitigationRequirements: MitigationRequirement[];

  // UI state
  isLoading: boolean;
  isSaving: boolean;
  saveError: string | null;
  hasUnsavedChanges: boolean;
  isDarkMode: boolean;
  showRiskInCanvas: boolean;
  
  // History for undo/redo
  history: { nodes: Node[]; edges: Edge[]; assets: Asset[]; boundaries: BoundaryData[] }[];
  historyIndex: number;

  // Actions
  toggleRiskInCanvas: () => void;
  fetchProject: () => Promise<void>;
  saveProject: (isAutosave?: boolean) => Promise<void>;
  
  // React Flow handlers
  onNodesChange: (changes: NodeChange[]) => void;
  onEdgesChange: (changes: EdgeChange[]) => void;
  onConnect: (connection: Connection) => void;
  
  // Diagram element manipulation
  addComponent: (type: 'Process' | 'Data Store' | 'Entity', name?: string, x?: number, y?: number) => void;
  addBoundary: (name?: string, x?: number, y?: number) => void;
  addAsset: (name?: string) => void;
  
  updateComponent: (id: string, updates: Partial<ComponentData>) => void;
  updateBoundary: (id: string, updates: Partial<BoundaryData>) => void;
  updateFlow: (id: string, updates: Partial<FlowData>) => void;
  updateAsset: (id: string, updates: Partial<Asset>) => void;
  deleteElement: (id: string, type: 'component' | 'boundary' | 'flow' | 'asset') => void;
  selectElement: (id: string | null, type: 'component' | 'boundary' | 'flow' | 'asset' | null) => void;
  addThreat: (threat: Omit<Threat, 'threat_id'>) => void;
  updateThreat: (id: string, updates: Partial<Threat>) => void;
  deleteThreat: (id: string) => void;
  addVulnerability: (vuln: Omit<Vulnerability, 'vulnerability_id'>) => void;
  updateVulnerability: (id: string, updates: Partial<Vulnerability>) => void;
  deleteVulnerability: (id: string) => void;
  addMitigationRequirement: (req: Omit<MitigationRequirement, 'req_id'>) => void;
  updateMitigationRequirement: (id: string, updates: Partial<MitigationRequirement>) => void;
  deleteMitigationRequirement: (id: string) => void;

  // History Actions
  pushHistory: () => void;
  undo: () => void;
  redo: () => void;
  toggleTheme: () => void;
}

// Generate high quality V4 UUIDs or Hex equivalent
const generateId = () => Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

export interface CVSSMetrics {
  AV: 'N' | 'A' | 'L' | 'P';
  AC: 'L' | 'H';
  PR: 'N' | 'L' | 'H';
  UI: 'N' | 'R';
  S: 'U' | 'C';
  C: 'N' | 'L' | 'H';
  I: 'N' | 'L' | 'H';
  A: 'N' | 'L' | 'H';
}

export const parseCVSSVector = (v: string): CVSSMetrics => {
  const defaults: CVSSMetrics = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' };
  if (!v || !v.startsWith('CVSS:3.')) return defaults;
  const parts = v.split('/');
  const metrics: CVSSMetrics = { ...defaults };
  parts.forEach(p => {
    const idx = p.indexOf(':');
    if (idx !== -1) {
      const key = p.substring(0, idx) as keyof CVSSMetrics;
      const val = p.substring(idx + 1);
      if (key in metrics) {
        (metrics as any)[key] = val;
      }
    }
  });
  return metrics;
};

export const generateCVSSVector = (m: CVSSMetrics): string => {
  return `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
};

export const calculateCVSSBaseScore = (metrics: CVSSMetrics): number => {
  const AVWeight = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const ACWeight = { L: 0.77, H: 0.44 };
  const UIWeight = { N: 0.85, R: 0.62 };
  const PRWeight = {
    U: { N: 0.85, L: 0.62, H: 0.27 },
    C: { N: 0.85, L: 0.68, H: 0.5 }
  };
  const CIAWeight = { N: 0, L: 0.22, H: 0.56 };

  const scopeChanged = metrics.S === 'C';
  const av = AVWeight[metrics.AV];
  const ac = ACWeight[metrics.AC];
  const pr = PRWeight[metrics.S][metrics.PR];
  const ui = UIWeight[metrics.UI];
  
  const exploitability = 8.22 * av * ac * pr * ui;
  
  const c = CIAWeight[metrics.C];
  const i = CIAWeight[metrics.I];
  const a = CIAWeight[metrics.A];
  
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  let impact = 0;
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }
  
  if (impact <= 0) return 0;
  
  let baseScore = 0;
  if (scopeChanged) {
    baseScore = Math.min(1.08 * (impact + exploitability), 10);
  } else {
    baseScore = Math.min(impact + exploitability, 10);
  }
  
  return Math.ceil(baseScore * 10) / 10;
};

export const useDesignerStore = create<DesignerState>((set, get) => ({
  projectName: 'New Project',
  metadata: null,
  nodes: [],
  edges: [],
  assets: [],
  customComponentTypes: [],
  selectedElementId: null,
  selectedElementType: null,
  threats: [],
  vulnerabilities: [],
  mitigationRequirements: [],
  isLoading: false,
  isSaving: false,
  saveError: null,
  hasUnsavedChanges: false,
  isDarkMode: false,
  showRiskInCanvas: true,
  history: [],
  historyIndex: -1,
  toggleTheme: () => set((state) => {
    const newTheme = !state.isDarkMode;
    if (newTheme) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    return { isDarkMode: newTheme };
  }),

  toggleRiskInCanvas: () => set((state) => ({ showRiskInCanvas: !state.showRiskInCanvas })),

  fetchProject: async () => {
    set({ isLoading: true, saveError: null });
    try {
      // 1. Fetch metadata
      const ts = new Date().getTime();
      const metaRes = await fetch(`/api/project/metadata?t=${ts}`, { cache: 'no-store' });
      let meta: ProjectMetadata | null = null;
      if (metaRes.ok) {
        meta = await metaRes.json();
      }

      // 2. Fetch architecture DFD state
      const res = await fetch(`/api/project?t=${ts}`, { cache: 'no-store' });
      if (!res.ok) throw new Error('Failed to load project');
      const data = await res.json();

      const assets: Asset[] = data.assets || [];
      const customComponentTypes: string[] = data.custom_component_types || [];

      // Convert Components to React Flow nodes
      const componentNodes: Node[] = (data.components || []).map((c: any) => ({
        id: c.component_id,
        type: 'componentNode',
        position: { x: c.x || 0, y: c.y || 0 },
        width: c.width || 120,
        height: c.height || 100,
        zIndex: 10,
        data: {
          component_id: c.component_id,
          name: c.name || 'Component',
          type: c.type || 'Service',
          element_type: c.element_type || 'Process',
          asset_type: c.asset_type || 'Informational',
          trust_boundary_id: c.trust_boundary_id || null,
          description: c.description || '',
          is_out_of_scope: c.is_out_of_scope || false,
          out_of_scope_justification: c.out_of_scope_justification || '',
        },
      }));

      // Convert Boundaries to React Flow nodes
      const boundaryNodes: Node[] = (data.boundaries || []).map((b: any) => ({
        id: b.boundary_id,
        type: 'boundaryNode',
        position: { x: b.x || 0, y: b.y || 0 },
        width: b.width || 250,
        height: b.height || 200,
        zIndex: -5,
        style: { width: b.width || 250, height: b.height || 200 },
        data: { ...b },
      }));

      const edges: Edge[] = (data.flows || []).map((f: any) => ({
        id: f.flow_id,
        source: f.source_id,
        target: f.target_id,
        label: f.protocol || '',
        markerEnd: { type: MarkerType.ArrowClosed },
        markerStart: f.is_bidirectional ? { type: MarkerType.ArrowClosed } : undefined,
        data: {
          ...f,
          assets: f.assets || [],
        },
      }));

      const nodes = [...boundaryNodes, ...componentNodes];

      const seenThreatIds = new Set<string>();
      const mappedThreats = (data.threats || []).map((t: any) => {
        let tid = t.threat_id;
        if (!tid || seenThreatIds.has(tid)) {
          tid = `threat_${generateId()}`;
        }
        seenThreatIds.add(tid);
        return {
          ...t,
          threat_id: tid
        };
      });

      const seenVulnIds = new Set<string>();
      const mappedVulns = (data.vulnerabilities || []).map((v: any) => {
        let vid = v.vulnerability_id;
        if (!vid || seenVulnIds.has(vid)) {
          vid = `vuln_${generateId()}`;
        }
        seenVulnIds.add(vid);
        return {
          ...v,
          vulnerability_id: vid
        };
      });

      set({
        projectName: meta?.project_name || 'ThreatPilot Project',
        metadata: meta,
        nodes,
        edges,
        assets,
        customComponentTypes,
        threats: mappedThreats,
        vulnerabilities: mappedVulns,
        mitigationRequirements: data.mitigation_requirements || [],
        isLoading: false,
        hasUnsavedChanges: false,
        history: [{ nodes, edges, assets, boundaries: (data.boundaries || []) }],
        historyIndex: 0,
      });
    } catch (e: any) {
      set({ isLoading: false, saveError: e.message });
    }
  },

  saveProject: async (isAutosave = false) => {
    const { nodes, edges, assets, customComponentTypes, threats, vulnerabilities, mitigationRequirements } = get();
    if (!isAutosave) {
      set({ isSaving: true });
    }
    
    try {
      const components = nodes
        .filter((n) => n.type === 'componentNode')
        .map((n) => ({
          component_id: n.id,
          name: n.data.name,
          type: n.data.type,
          element_type: n.data.element_type,
          asset_type: n.data.asset_type,
          trust_boundary_id: n.data.trust_boundary_id,
          description: n.data.description,
          is_out_of_scope: n.data.is_out_of_scope,
          out_of_scope_justification: n.data.out_of_scope_justification,
          x: n.position.x,
          y: n.position.y,
          width: n.width || 120,
          height: n.height || 100,
        }));

      const boundaries = nodes
        .filter((n) => n.type === 'boundaryNode')
        .map((n) => ({
          boundary_id: n.id,
          name: n.data.name,
          type: n.data.type,
          description: n.data.description,
          parent_boundary_id: n.data.parent_boundary_id,
          x: n.position.x,
          y: n.position.y,
          width: n.width || 250,
          height: n.height || 200,
        }));

      const flows = edges.map((e) => ({
        flow_id: e.id,
        name: e.data.name || e.label || 'Data Flow',
        source_id: e.source,
        target_id: e.target,
        protocol: e.data.protocol,
        description: e.data.description,
        is_out_of_scope: e.data.is_out_of_scope,
        out_of_scope_justification: e.data.out_of_scope_justification,
        is_bidirectional: e.data.is_bidirectional,
        trust_boundary_id: e.data.trust_boundary_id,
        authentication: e.data.authentication || '',
        encryption: e.data.encryption || '',
        assets: e.data.assets || [],
        start_x: 0,
        start_y: 0,
        end_x: 0,
        end_y: 0,
      }));

      const payload = {
        components,
        boundaries,
        flows,
        assets,
        custom_component_types: customComponentTypes,
        threats,
        vulnerabilities,
        mitigation_requirements: mitigationRequirements,
      };

      const endpoint = isAutosave ? '/api/project/autosave' : '/api/project';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) throw new Error('Failed to save project data');

      set({ isSaving: false, hasUnsavedChanges: false });
    } catch (e: any) {
      set({ isSaving: false, saveError: e.message });
    }
  },

  onNodesChange: (changes: NodeChange[]) => {
    const currentNodes = get().nodes;
    const newNodes = applyNodeChanges(changes, currentNodes);
    let modifiedNodes = [...newNodes];

    const positionDrags = changes.filter(c => c.type === 'position' && (c as any).dragging) as any[];
    if (positionDrags.length > 0) {
      for (const drag of positionDrags) {
        const node = modifiedNodes.find(n => n.id === drag.id);
        if (!node) continue;
        if (node.type === 'boundaryNode') {
          const oldNode = currentNodes.find(n => n.id === node.id);
          if (oldNode && drag.position) {
            const dx = drag.position.x - oldNode.position.x;
            const dy = drag.position.y - oldNode.position.y;
            if (dx !== 0 || dy !== 0) {
              modifiedNodes = modifiedNodes.map(n => {
                if (n.type === 'componentNode' && n.data.trust_boundary_id === node.id) {
                  return {
                    ...n,
                    position: { x: n.position.x + dx, y: n.position.y + dy }
                  };
                }
                return n;
              });
            }
          }
        }
      }
    }

    const positionDragEnd = changes.filter(c => c.type === 'position' && !(c as any).dragging) as any[];
    if (positionDragEnd.length > 0) {
      for (const drag of positionDragEnd) {
        const node = modifiedNodes.find(n => n.id === drag.id);
        if (node && node.type === 'componentNode') {
          const nx = node.position.x;
          const ny = node.position.y;
          let newBoundaryId: string | null = null;
          let minArea = Infinity;
          for (const b of modifiedNodes) {
            if (b.type === 'boundaryNode') {
              const bx = b.position.x;
              const by = b.position.y;
              const bw = b.width || 250;
              const bh = b.height || 200;
              if (nx >= bx && nx <= bx + bw && ny >= by && ny <= by + bh) {
                const area = bw * bh;
                if (area < minArea) {
                  minArea = area;
                  newBoundaryId = b.id;
                }
              }
            }
          }
          if (node.data.trust_boundary_id !== newBoundaryId) {
            modifiedNodes = modifiedNodes.map(n => {
              if (n.id === node.id) {
                return {
                  ...n,
                  data: { ...n.data, trust_boundary_id: newBoundaryId }
                };
              }
              return n;
            });
          }
        }
      }
    }

    for (const b of modifiedNodes) {
      if (b.type === 'boundaryNode') {
        const bx = b.position.x;
        const by = b.position.y;
        let maxRight = bx + (b.width || 250);
        let maxBottom = by + (b.height || 200);
        let resized = false;
        const childComponents = modifiedNodes.filter(n => n.type === 'componentNode' && n.data.trust_boundary_id === b.id);
        for (const child of childComponents) {
          const cx = child.position.x + (child.width || 120);
          const cy = child.position.y + (child.height || 100);
          if (cx > maxRight) { maxRight = cx + 20; resized = true; }
          if (cy > maxBottom) { maxBottom = cy + 20; resized = true; }
        }
        if (resized) {
          b.width = maxRight - bx;
          b.height = maxBottom - by;
          b.style = { ...b.style, width: b.width, height: b.height };
        }
      }
    }

    set({ nodes: modifiedNodes, hasUnsavedChanges: true });
    if (changes.some(c => c.type === 'position' && !c.dragging)) {
      get().pushHistory();
    }
  },

  onEdgesChange: (changes: EdgeChange[]) => {
    set({
      edges: applyEdgeChanges(changes, get().edges),
      hasUnsavedChanges: true,
    });
    if (changes.some(c => c.type === 'remove')) {
      get().pushHistory();
    }
  },

  onConnect: (connection: Connection) => {
    if (!connection.source || !connection.target) return;
    const newEdgeId = generateId();
    const newEdge: Edge = {
      id: newEdgeId,
      source: connection.source,
      target: connection.target,
      label: 'HTTPS',
      markerEnd: { type: MarkerType.ArrowClosed },
      data: {
        flow_id: newEdgeId,
        name: 'Data Flow',
        source_id: connection.source,
        target_id: connection.target,
        protocol: 'HTTPS',
        description: '',
        is_out_of_scope: false,
        out_of_scope_justification: '',
        is_bidirectional: false,
        trust_boundary_id: null,
        authentication: 'None',
        encryption: 'TLS',
        assets: [],
      },
    };

    set({
      edges: addEdge(newEdge, get().edges),
      hasUnsavedChanges: true,
    });
    get().pushHistory();
  },

  addComponent: (type, name, x = 100, y = 100) => {
    const id = generateId();
    const newNode: Node = {
      id,
      type: 'componentNode',
      position: { x, y },
      width: 120,
      height: 100,
      zIndex: 10,
      data: {
        component_id: id,
        name: name || `New ${type}`,
        type: type === 'Process' ? 'Web Server' : type === 'Data Store' ? 'Database' : 'User',
        element_type: type,
        asset_type: 'Informational',
        trust_boundary_id: null,
        description: '',
        is_out_of_scope: false,
        out_of_scope_justification: '',
      },
    };

    set((state) => ({
      nodes: [...state.nodes, newNode],
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  addBoundary: (name = 'New Trust Boundary', x = 150, y = 150) => {
    const id = generateId();
    const newNode: Node = {
      id,
      type: 'boundaryNode',
      position: { x, y },
      width: 300,
      height: 200,
      zIndex: -5,
      style: { width: 300, height: 200 },
      data: {
        boundary_id: id,
        name,
        type: 'Internal',
        description: '',
        parent_boundary_id: null,
      },
    };

    set((state) => ({
      nodes: [...state.nodes, newNode],
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  addAsset: (name = 'New Asset') => {
    const id = generateId();
    const newAsset: Asset = {
      asset_id: id,
      name,
      type: 'Informational',
      description: '',
      criticality: 'Medium',
      is_out_of_scope: false,
      out_of_scope_justification: '',
    };

    set((state) => ({
      assets: [...state.assets, newAsset],
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  updateComponent: (id, updates) => {
    set((state) => ({
      nodes: state.nodes.map((n) => {
        if (n.id === id) {
          return {
            ...n,
            data: { ...n.data, ...updates },
          };
        }
        return n;
      }),
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  updateBoundary: (id, updates) => {
    set((state) => ({
      nodes: state.nodes.map((n) => {
        if (n.id === id) {
          return {
            ...n,
            data: { ...n.data, ...updates },
          };
        }
        return n;
      }),
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  updateFlow: (id, updates) => {
    set((state) => {
      const newEdges = state.edges.map((edge) => {
        if (edge.id === id) {
          const newData = { ...edge.data, ...updates };
          const markerStart = newData.is_bidirectional ? { type: MarkerType.ArrowClosed } : undefined;
          
          return { 
            ...edge, 
            data: newData, 
            label: newData.protocol || '',
            markerEnd: { type: MarkerType.ArrowClosed },
            markerStart 
          };
        }
        return edge;
      });
      return { edges: newEdges, hasUnsavedChanges: true };
    });
    get().pushHistory();
  },

  updateAsset: (id, updates) => {
    set((state) => ({
      assets: state.assets.map((a) => (a.asset_id === id ? { ...a, ...updates } : a)),
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  deleteVulnerability: (id) => {
    set((state) => ({
      vulnerabilities: state.vulnerabilities.filter((v) => v.vulnerability_id !== id),
      threats: state.threats.map((t) => ({
        ...t,
        vulnerability_ids: (t.vulnerability_ids || []).filter((vid) => vid !== id),
      })),
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  addThreat: (threat) => {
    set((state) => ({
      threats: [...state.threats, { ...threat, threat_id: `TH-${generateId()}` }],
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  updateThreat: (id, updates) => {
    set((state) => ({
      threats: state.threats.map((t) => (t.threat_id === id ? { ...t, ...updates } : t)),
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  deleteThreat: (id) => {
    set((state) => ({
      threats: state.threats.filter((t) => t.threat_id !== id),
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  addVulnerability: (vuln) => {
    set((state) => ({
      vulnerabilities: [...state.vulnerabilities, { ...vuln, vulnerability_id: `VULN-${generateId()}` }],
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  updateVulnerability: (id, updates) => {
    set((state) => ({
      vulnerabilities: state.vulnerabilities.map((v) => (v.vulnerability_id === id ? { ...v, ...updates } : v)),
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  addMitigationRequirement: (req) => {
    set((state) => ({
      mitigationRequirements: [...state.mitigationRequirements, { ...req, req_id: `MIT-${generateId()}` }],
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  updateMitigationRequirement: (id, updates) => {
    set((state) => ({
      mitigationRequirements: state.mitigationRequirements.map((r) => (r.req_id === id ? { ...r, ...updates } : r)),
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  deleteMitigationRequirement: (id) => {
    set((state) => ({
      mitigationRequirements: state.mitigationRequirements.filter((r) => r.req_id !== id),
      hasUnsavedChanges: true,
    }));
    get().pushHistory();
  },

  deleteElement: (id, type) => {
    set((state) => {
      let nodes = state.nodes;
      let edges = state.edges;
      let assets = state.assets;

      if (type === 'component') {
        nodes = nodes.filter((n) => n.id !== id);
        // Cascading delete connected flows
        edges = edges.filter((e) => e.source !== id && e.target !== id);
      } else if (type === 'boundary') {
        nodes = nodes.filter((n) => n.id !== id);
        // Detach components inside this boundary
        nodes = nodes.map((n) => {
          if (n.type === 'componentNode' && n.data.trust_boundary_id === id) {
            return { ...n, data: { ...n.data, trust_boundary_id: null } };
          }
          if (n.type === 'boundaryNode' && n.data.parent_boundary_id === id) {
            return { ...n, data: { ...n.data, parent_boundary_id: null } };
          }
          return n;
        });
      } else if (type === 'flow') {
        edges = edges.filter((e) => e.id !== id);
      } else if (type === 'asset') {
        assets = assets.filter((a) => a.asset_id !== id);
        // Remove asset reference from flows
        edges = edges.map((e) => {
          if (e.data.assets && e.data.assets.includes(id)) {
            return {
              ...e,
              data: {
                ...e.data,
                assets: e.data.assets.filter((aid: string) => aid !== id),
              },
            };
          }
          return e;
        });
      }

      return {
        nodes,
        edges,
        assets,
        selectedElementId: state.selectedElementId === id ? null : state.selectedElementId,
        selectedElementType: state.selectedElementId === id ? null : state.selectedElementType,
        hasUnsavedChanges: true,
      };
    });
    get().pushHistory();
  },

  selectElement: (id, type) => {
    set({ selectedElementId: id, selectedElementType: type });
  },

  pushHistory: () => {
    const { nodes, edges, assets, history, historyIndex } = get();
    // Truncate future if we performed actions after an undo
    const newHistory = history.slice(0, historyIndex + 1);
    
    // Save boundaries list specifically for schema mapping
    const boundaries = nodes
      .filter(n => n.type === 'boundaryNode')
      .map(n => n.data as BoundaryData);

    set({
      history: [...newHistory, { nodes: JSON.parse(JSON.stringify(nodes)), edges: JSON.parse(JSON.stringify(edges)), assets: JSON.parse(JSON.stringify(assets)), boundaries }],
      historyIndex: newHistory.length,
    });
  },

  undo: () => {
    const { history, historyIndex } = get();
    if (historyIndex > 0) {
      const targetIndex = historyIndex - 1;
      const snapshot = history[targetIndex];
      set({
        nodes: snapshot.nodes,
        edges: snapshot.edges,
        assets: snapshot.assets,
        historyIndex: targetIndex,
        hasUnsavedChanges: true,
        selectedElementId: null,
        selectedElementType: null,
      });
    }
  },

  redo: () => {
    const { history, historyIndex } = get();
    if (historyIndex < history.length - 1) {
      const targetIndex = historyIndex + 1;
      const snapshot = history[targetIndex];
      set({
        nodes: snapshot.nodes,
        edges: snapshot.edges,
        assets: snapshot.assets,
        historyIndex: targetIndex,
        hasUnsavedChanges: true,
        selectedElementId: null,
        selectedElementType: null,
      });
    }
  },
}));
