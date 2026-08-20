import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryGuardPageArmDisarmTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_guard_page_arm_disarm',
    'Dynamically toggle PAGE_GUARD flags on targeted memory pages, re-arm triggered guard pages, and inspect trap triggers.',
    {
      action: z.enum(['arm_guard_page', 'disarm_guard_page', 'list_armed_pages']).describe('Guard page action'),
      address: z.string().optional().describe('Virtual address of memory page'),
      size: z.number().default(4096).describe('Byte size of memory region to guard'),
    },
    async ({ action, address, size }) => {
      let data: unknown;
      switch (action) {
        case 'arm_guard_page':
          data = await httpClient.post('/api/guard_toggle/arm', { address, size });
          break;
        case 'disarm_guard_page':
          data = await httpClient.post('/api/guard_toggle/disarm', { address, size });
          break;
        case 'list_armed_pages':
          data = await httpClient.get('/api/guard_toggle/list');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
