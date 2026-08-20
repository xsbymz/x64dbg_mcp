import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRopGadgetClusterAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_rop_gadget_cluster_analyzer',
    'Cluster ROP gadgets by register transformations (e.g. Memory Load, Memory Store, Arithmetic, Stack Pivot, Control Flow).',
    {
      action: z.enum(['cluster_all_gadgets', 'get_memory_load_gadgets', 'get_arithmetic_gadgets']).describe('Gadget cluster action'),
      module_name: z.string().optional().describe('Module name to scan for gadget clusters'),
    },
    async ({ action, module_name }) => {
      let data: unknown;
      switch (action) {
        case 'cluster_all_gadgets':
          data = await httpClient.post('/api/gadget_cluster/all', { module_name });
          break;
        case 'get_memory_load_gadgets':
          data = await httpClient.post('/api/gadget_cluster/load', { module_name });
          break;
        case 'get_arithmetic_gadgets':
          data = await httpClient.post('/api/gadget_cluster/arithmetic', { module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
