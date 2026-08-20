import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCallGraphExporterTools(server: McpServer) {
  server.tool(
    'x64dbg_call_graph_exporter',
    'Export whole-module and inter-procedural call graphs into GEXF (Gephi), GraphML, or Cytoscape JSON network visualization graph formats.',
    {
      action: z.enum(['export_gexf_graph', 'export_graphml_graph', 'export_cytoscape_json']).describe('Graph exporter action'),
      module_name: z.string().optional().describe('Target module name'),
    },
    async ({ action, module_name }) => {
      let data: unknown;
      switch (action) {
        case 'export_gexf_graph':
          data = await httpClient.post('/api/call_graph_export/gexf', { module_name });
          break;
        case 'export_graphml_graph':
          data = await httpClient.post('/api/call_graph_export/graphml', { module_name });
          break;
        case 'export_cytoscape_json':
          data = await httpClient.post('/api/call_graph_export/cytoscape', { module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
