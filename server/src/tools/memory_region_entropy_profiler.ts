import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryRegionEntropyProfilerTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_region_entropy_profiler',
    'Generate continuous mathematical entropy graphs (Shannon, Min-entropy, Collision entropy) across any custom memory address span.',
    {
      action: z.enum(['profile_span', 'calculate_min_entropy', 'get_entropy_histogram']).describe('Entropy profiler action'),
      address: z.string().describe('Base address of the memory span to profile'),
      size: z.number().describe('Size in bytes to profile'),
      block_size: z.number().optional().describe('Sub-block window size in bytes (default 256)'),
    },
    async ({ action, address, size, block_size }) => {
      let data: unknown;
      switch (action) {
        case 'profile_span':
          data = await httpClient.post('/api/entropy_profile/span', { address, size, block_size });
          break;
        case 'calculate_min_entropy':
          data = await httpClient.post('/api/entropy_profile/min_entropy', { address, size });
          break;
        case 'get_entropy_histogram':
          data = await httpClient.post('/api/entropy_profile/histogram', { address, size });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
