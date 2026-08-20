import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSehLeafFunctionUnwinderTools(server: McpServer) {
  server.tool(
    'x64dbg_seh_leaf_function_unwinder',
    'Unwind and reconstruct call stack frames for x64 leaf functions (functions without .pdata RUNTIME_FUNCTION entries that do not modify RSP or non-volatile registers).',
    {
      action: z.enum(['unwind_leaf_frame', 'verify_leaf_status', 'find_caller_return_address']).describe('Leaf unwinder action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'unwind_leaf_frame':
          data = await httpClient.get('/api/leaf_unwind/frame');
          break;
        case 'verify_leaf_status':
          data = await httpClient.get('/api/leaf_unwind/status');
          break;
        case 'find_caller_return_address':
          data = await httpClient.get('/api/leaf_unwind/caller');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
