import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFlsSlotDataWalkerTools(server: McpServer) {
  server.tool(
    'x64dbg_fls_slot_data_walker',
    'Walk Fiber Local Storage (FLS) per-fiber data slot arrays across all active thread fibers to inspect thread-local storage slots.',
    {
      action: z.enum(['walk_all_fls_slots', 'read_slot_value', 'list_allocated_fls_indices']).describe('FLS walker action'),
      slot_index: z.number().optional().describe('FLS slot index to inspect'),
    },
    async ({ action, slot_index }) => {
      let data: unknown;
      switch (action) {
        case 'walk_all_fls_slots':
          data = await httpClient.get('/api/fls_walker/all');
          break;
        case 'read_slot_value':
          data = await httpClient.post('/api/fls_walker/read_slot', { slot_index });
          break;
        case 'list_allocated_fls_indices':
          data = await httpClient.get('/api/fls_walker/indices');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
