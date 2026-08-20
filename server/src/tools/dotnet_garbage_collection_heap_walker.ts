import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDotnetGarbageCollectionHeapWalkerTools(server: McpServer) {
  server.tool(
    'x64dbg_dotnet_garbage_collection_heap_walker',
    'Walk .NET CLR GC heaps (Generation 0, 1, 2, LOH, POH), inspect GC segments, and resolve live object sizes.',
    {
      action: z.enum(['walk_gc_generations', 'list_gc_segments', 'get_loh_objects']).describe('GC walker action'),
      generation: z.number().min(0).max(2).optional().describe('Filter by GC Generation (0, 1, 2)'),
    },
    async ({ action, generation }) => {
      let data: unknown;
      switch (action) {
        case 'walk_gc_generations':
          data = await httpClient.post('/api/clr_gc/generations', { generation });
          break;
        case 'list_gc_segments':
          data = await httpClient.get('/api/clr_gc/segments');
          break;
        case 'get_loh_objects':
          data = await httpClient.get('/api/clr_gc/loh');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
