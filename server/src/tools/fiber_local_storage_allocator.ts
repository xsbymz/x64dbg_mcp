import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFiberLocalStorageAllocatorTools(server: McpServer) {
  server.tool(
    'x64dbg_fiber_local_storage_allocator',
    'Manage and dynamically allocate new FLS indices (FlsAlloc, FlsFree, FlsSetValue) inside target process memory space.',
    {
      action: z.enum(['alloc_slot', 'free_slot', 'set_slot_value', 'list_allocated_slots']).describe('FLS allocator action'),
      slot_index: z.number().optional().describe('FLS slot index to free or write to'),
      value: z.string().optional().describe('64-bit value to store in the FLS slot'),
    },
    async ({ action, slot_index, value }) => {
      let data: unknown;
      switch (action) {
        case 'alloc_slot':
          data = await httpClient.post('/api/fls_alloc/alloc', {});
          break;
        case 'free_slot':
          data = await httpClient.post('/api/fls_alloc/free', { slot_index });
          break;
        case 'set_slot_value':
          data = await httpClient.post('/api/fls_alloc/set', { slot_index, value });
          break;
        case 'list_allocated_slots':
          data = await httpClient.get('/api/fls_alloc/list');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
