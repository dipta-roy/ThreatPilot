import { Node, Edge } from 'reactflow';

export function generateMermaidDiagram(nodes: Node[], edges: Edge[]): string {
  const components = nodes.filter((n) => n.type === 'componentNode');
  const boundaries = nodes.filter((n) => n.type === 'boundaryNode');

  let mermaid = 'flowchart LR\n';

  // Helper to sanitize name for ID use
  const makeId = (name: string) => name.replace(/[^a-zA-Z0-9]/g, '');

  // 1. Generate trust boundaries as subgraphs
  boundaries.forEach((b) => {
    const boundaryId = makeId(b.data.name) + b.id.substring(0, 4);
    mermaid += `  subgraph ${boundaryId} ["${b.data.name} [${b.data.type || 'Trust Boundary'}]"]\n`;
    
    // List components inside this boundary
    const innerComponents = components.filter((c) => c.data.trust_boundary_id === b.id);
    innerComponents.forEach((c) => {
      const compId = makeId(c.data.name) + c.id.substring(0, 4);
      // Format node shape by type
      let shape = `["${c.data.name}"]`;
      if (c.data.element_type === 'Data Store') {
        shape = `[("${c.data.name}")]`; // Database shape
      } else if (c.data.element_type === 'Entity') {
        shape = `(("${c.data.name}"))`; // Circle shape
      }
      mermaid += `    ${compId}${shape}\n`;
    });
    mermaid += '  end\n\n';
  });

  // 2. Generate root components (outside any boundary)
  const rootComponents = components.filter((c) => !c.data.trust_boundary_id);
  rootComponents.forEach((c) => {
    const compId = makeId(c.data.name) + c.id.substring(0, 4);
    let shape = `["${c.data.name}"]`;
    if (c.data.element_type === 'Data Store') {
      shape = `[("${c.data.name}")]`;
    } else if (c.data.element_type === 'Entity') {
      shape = `(("${c.data.name}"))`;
    }
    mermaid += `  ${compId}${shape}\n`;
  });

  // 3. Generate flows
  edges.forEach((e) => {
    const sourceNode = components.find((n) => n.id === e.source);
    const targetNode = components.find((n) => n.id === e.target);
    
    if (sourceNode && targetNode) {
      const sourceId = makeId(sourceNode.data.name) + sourceNode.id.substring(0, 4);
      const targetId = makeId(targetNode.data.name) + targetNode.id.substring(0, 4);
      const label = e.data.protocol || e.data.name || 'Flow';
      
      mermaid += `  ${sourceId} -->|"${label}"| ${targetId}\n`;
    }
  });

  return mermaid;
}
