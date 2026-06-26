import { Node, Edge } from 'reactflow';

export function generateAsciiArchitecture(nodes: Node[], edges: Edge[]): string {
  const components = nodes.filter((n) => n.type === 'componentNode');
  const boundaries = nodes.filter((n) => n.type === 'boundaryNode');

  let ascii = '';
  ascii += '======================================================================\n';
  ascii += '                      THREATPILOT ASCII ARCHITECTURE                  \n';
  ascii += '======================================================================\n\n';

  // 1. Group components by boundaries
  ascii += '┌────────────────────────────────────────────────────────────────────┐\n';
  ascii += '│                    TRUST BOUNDARIES & COMPONENTS                   │\n';
  ascii += '└────────────────────────────────────────────────────────────────────┘\n';

  boundaries.forEach((b) => {
    ascii += `[+] ${b.data.name} (Type: ${b.data.type || 'Internal'})\n`;
    const innerComponents = components.filter((c) => c.data.trust_boundary_id === b.id);
    if (innerComponents.length === 0) {
      ascii += '    └── (Empty Boundary)\n';
    } else {
      innerComponents.forEach((c, idx) => {
        const isLast = idx === innerComponents.length - 1;
        const branch = isLast ? '    └──' : '    ├──';
        ascii += `${branch} [${c.data.element_type}] ${c.data.name} (${c.data.type})\n`;
      });
    }
    ascii += '\n';
  });

  const rootComponents = components.filter((c) => !c.data.trust_boundary_id);
  if (rootComponents.length > 0) {
    ascii += '[x] Outside Any Trust Boundary\n';
    rootComponents.forEach((c, idx) => {
      const isLast = idx === rootComponents.length - 1;
      const branch = isLast ? '    └──' : '    ├──';
      ascii += `${branch} [${c.data.element_type}] ${c.data.name} (${c.data.type})\n`;
    });
    ascii += '\n';
  }

  // 2. Map data flows
  ascii += '┌────────────────────────────────────────────────────────────────────┐\n';
  ascii += '│                       DATA FLOWS & CONNECTIONS                     │\n';
  ascii += '└────────────────────────────────────────────────────────────────────┘\n';

  if (edges.length === 0) {
    ascii += '  No data flows defined.\n';
  } else {
    components.forEach((c) => {
      const outgoingEdges = edges.filter((e) => e.source === c.id);
      if (outgoingEdges.length > 0) {
        ascii += ` ${c.data.name}\n`;
        outgoingEdges.forEach((e, idx) => {
          const targetNode = components.find((t) => t.id === e.target);
          const targetName = targetNode ? targetNode.data.name : 'Unknown Target';
          const isLast = idx === outgoingEdges.length - 1;
          const branch = isLast ? '  └──' : '  ├──';
          const protocol = e.data.protocol ? ` [${e.data.protocol}] ` : ' ';
          const encryption = e.data.encryption ? ` (${e.data.encryption})` : '';
          ascii += `${branch}──${protocol}──> ${targetName}${encryption}\n`;
        });
        ascii += '\n';
      }
    });
  }

  return ascii;
}
