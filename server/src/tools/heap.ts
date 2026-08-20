import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHeapTools(server: McpServer) {
  server.tool(
    'x64dbg_heap',
    'Windows heap forensics: enumerate heaps, walk segments and chunks, detect corruption. ' +
    'Actions: list (enumerate all process heaps), walk (walk a specific heap: header, segments, chunks), ' +
    'corruption (check heap metadata integrity for double-free, invalid pointers, signature mismatch).',
    {
      action: z.enum(['list', 'walk', 'corruption']).describe('Heap action'),
      address: z.string().optional().describe('Heap base address (required for walk and corruption)')
    },
    async ({ action, address }) => {
      try {
        let data: unknown;
        const params: Record<string, string> = {};
        if (address) params.address = address;

        switch (action) {
          case 'list':
            data = await httpClient.get('/api/heap/list');
            break;
          case 'walk':
            if (!address) throw new Error('address is required for walk action');
            data = await httpClient.get('/api/heap/walk', params);
            break;
          case 'corruption':
            if (!address) throw new Error('address is required for corruption action');
            data = await httpClient.get('/api/heap/corruption', params);
            break;
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
