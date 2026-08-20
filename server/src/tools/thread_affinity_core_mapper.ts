import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerThreadAffinityCoreMapperTools(server: McpServer) {
  server.tool(
    'x64dbg_thread_affinity_core_mapper',
    'Query and configure thread ideal processor, affinity masks (SetThreadAffinityMask), and NUMA node core assignments across active threads.',
    {
      action: z.enum(['list_thread_affinities', 'set_thread_affinity', 'get_numa_topology']).describe('Affinity action'),
      thread_id: z.number().optional().describe('Target Thread ID'),
      affinity_mask: z.string().optional().describe('Bitmask hex string for allowed CPU cores (e.g. 0x01, 0x0F)'),
    },
    async ({ action, thread_id, affinity_mask }) => {
      let data: unknown;
      switch (action) {
        case 'list_thread_affinities':
          data = await httpClient.get('/api/thread_affinity/list');
          break;
        case 'set_thread_affinity':
          data = await httpClient.post('/api/thread_affinity/set', { thread_id, affinity_mask });
          break;
        case 'get_numa_topology':
          data = await httpClient.get('/api/thread_affinity/numa');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
