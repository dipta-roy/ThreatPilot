import { useCallback, useState } from 'react';
import ReactFlow, { MiniMap, Controls, Background, useNodesState, useEdgesState, addEdge } from 'reactflow';
import 'reactflow/dist/style.css';

const initialNodes = [
  { id: '1', position: { x: 250, y: 50 }, data: { label: 'Internet User (Actor)' } },
  { id: '2', position: { x: 250, y: 150 }, data: { label: 'API Gateway (DMZ)' } },
  { id: '3', position: { x: 250, y: 250 }, data: { label: 'Auth Service (Internal)' } },
  { id: '4', position: { x: 250, y: 350 }, data: { label: 'Database (Restricted)' } },
];

const initialEdges = [
  { id: 'e1-2', source: '1', target: '2', label: 'HTTPS' },
  { id: 'e2-3', source: '2', target: '3', label: 'gRPC' },
  { id: 'e3-4', source: '3', target: '4', label: 'TCP/SQL' },
];

export default function ThreatGraphV2() {
  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [menu, setMenu] = useState<{ id: string, top: number, left: number } | null>(null);

  const onConnect = useCallback((params: any) => setEdges((eds) => addEdge(params, eds)), [setEdges]);

  const onNodeContextMenu = useCallback((event: any, node: any) => {
    event.preventDefault();
    setMenu({ id: node.id, top: event.clientY - 60, left: event.clientX });
  }, []);

  const onPaneClick = useCallback(() => setMenu(null), []);

  const handleAction = (action: string) => {
    if (menu) {
      console.log(`Action ${action} triggered on node ${menu.id}`);
      alert(`Action '${action}' on node ${menu.id} queued for processing.`);
    }
    setMenu(null);
  };

  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column' }}>
      <header style={{ padding: '1rem', backgroundColor: '#1a1a1a', color: 'white', fontWeight: 'bold' }}>
        ThreatPilot - V2 Architecture Map Integration
      </header>
      <div style={{ flex: 1, backgroundColor: '#f9f9f9', position: 'relative' }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onNodeContextMenu={onNodeContextMenu}
          onPaneClick={onPaneClick}
          fitView
        >
          <Controls />
          <MiniMap />
          <Background gap={12} size={1} />
        </ReactFlow>
        {menu && (
          <div style={{
            position: 'absolute', top: menu.top, left: menu.left,
            backgroundColor: 'white', border: '1px solid #ccc', borderRadius: '4px',
            boxShadow: '0 2px 10px rgba(0,0,0,0.1)', zIndex: 1000, padding: '4px 0'
          }}>
            <button style={{ display: 'block', width: '100%', padding: '8px 16px', border: 'none', background: 'none', cursor: 'pointer', textAlign: 'left', fontWeight: 500 }} onClick={() => handleAction('Generate Threats')}>Generate Threats</button>
            <button style={{ display: 'block', width: '100%', padding: '8px 16px', border: 'none', background: 'none', cursor: 'pointer', textAlign: 'left', fontWeight: 500 }} onClick={() => handleAction('Generate Abuse Cases')}>Generate Abuse Cases</button>
            <button style={{ display: 'block', width: '100%', padding: '8px 16px', border: 'none', background: 'none', cursor: 'pointer', textAlign: 'left', fontWeight: 500 }} onClick={() => handleAction('Generate Mitigations')}>Generate Mitigations</button>
            <hr style={{ margin: '4px 0', border: 'none', borderTop: '1px solid #eee' }} />
            <button style={{ display: 'block', width: '100%', padding: '8px 16px', border: 'none', background: 'none', cursor: 'pointer', textAlign: 'left', fontWeight: 500 }} onClick={() => handleAction('Generate Test Cases')}>Generate Test Cases</button>
            <button style={{ display: 'block', width: '100%', padding: '8px 16px', border: 'none', background: 'none', cursor: 'pointer', textAlign: 'left', fontWeight: 500 }} onClick={() => handleAction('Generate Security Requirements')}>Generate Security Requirements</button>
            <button style={{ display: 'block', width: '100%', padding: '8px 16px', border: 'none', background: 'none', cursor: 'pointer', textAlign: 'left', fontWeight: 500 }} onClick={() => handleAction('Generate Pentest Checklist')}>Generate Pentest Checklist</button>
          </div>
        )}
      </div>
    </div>
  );
}
