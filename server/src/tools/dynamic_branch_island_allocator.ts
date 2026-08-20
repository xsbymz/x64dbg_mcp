import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDynamicBranchIslandAllocatorTools(server: McpServer) {
  server.tool(
    'x64dbg_dynamic_branch_island_allocator',
    'Allocate 64-bit far branch trampoline relay islands in large address spaces within +/-2GB of source and target.',
    {
      action: z.enum(['allocate_relay_island', 'list_active_islands', 'free_island']).describe('Relay island action'),
      target_address: z.string().optional().describe('Address the branch island will redirect to'),
      source_address: z.string().optional().describe('Near source address needing +/-2GB reach'),
      island_id: z.string().optional().describe('Island identifier for freeing'),
    },
    async ({ action, target_address, source_address, island_id }) => {
      let data: unknown;
      switch (action) {
        case 'allocate_relay_island':
          data = await httpClient.post('/api/branch_island/allocate', { target_address, source_address });
          break;
        case 'list_active_islands':
          data = await httpClient.get('/api/branch_island/list');
          break;
        case 'free_island':
          data = await httpClient.post('/api/branch_island/free', { island_id });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
