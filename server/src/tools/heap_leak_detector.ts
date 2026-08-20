import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHeapLeakDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_heap_leak_detector',
    'Detect memory leaks in user-mode heaps: snapshot active allocations, diff against previous snapshots, and track unreferenced allocated heap blocks.',
    {
      action: z.enum(['take_allocation_snapshot', 'compare_snapshots', 'list_unreferenced_blocks']).describe('Heap leak action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'take_allocation_snapshot':
          data = await httpClient.get('/api/heap_leak/snapshot');
          break;
        case 'compare_snapshots':
          data = await httpClient.get('/api/heap_leak/compare');
          break;
        case 'list_unreferenced_blocks':
          data = await httpClient.get('/api/heap_leak/unreferenced');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
