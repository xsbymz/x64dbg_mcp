import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFlowVisualizerTools(server: McpServer) {
  server.tool(
    'x64dbg_flow_visualizer',
    'Generate dynamic execution flow graphs, basic block transition heatmaps, and export interactive diagrams in Mermaid or Graphviz DOT formats from live traces.',
    {
      action: z.enum(['export_mermaid_cfg', 'export_graphviz_dot', 'get_transition_heatmap', 'trace_slice']).describe('Visualization format/action'),
      start_address: z.string().optional().describe('Start address of function or trace slice'),
      end_address: z.string().optional().describe('End address of function or trace slice'),
    },
    async ({ action, start_address, end_address }) => {
      let data: unknown;
      switch (action) {
        case 'export_mermaid_cfg':
          data = await httpClient.post('/api/flow/mermaid_cfg', { start_address, end_address });
          break;
        case 'export_graphviz_dot':
          data = await httpClient.post('/api/flow/graphviz_dot', { start_address, end_address });
          break;
        case 'get_transition_heatmap':
          data = await httpClient.post('/api/flow/transition_heatmap', { start_address });
          break;
        case 'trace_slice':
          data = await httpClient.post('/api/flow/trace_slice', { start_address, end_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
