import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFlsCallbackDispatcherTools(server: McpServer) {
  server.tool(
    'x64dbg_fls_callback_dispatcher',
    'Dispatch, trace, and test user-defined Fiber Local Storage (FLS) termination callbacks registered with FlsAlloc.',
    {
      action: z.enum(['list_fls_callbacks', 'test_callback_invocation', 'simulate_fiber_cleanup']).describe('FLS callback action'),
      slot_index: z.number().optional().describe('FLS slot index'),
    },
    async ({ action, slot_index }) => {
      let data: unknown;
      switch (action) {
        case 'list_fls_callbacks':
          data = await httpClient.get('/api/fls_cb/list');
          break;
        case 'test_callback_invocation':
          data = await httpClient.post('/api/fls_cb/test', { slot_index });
          break;
        case 'simulate_fiber_cleanup':
          data = await httpClient.post('/api/fls_cb/simulate', { slot_index });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
