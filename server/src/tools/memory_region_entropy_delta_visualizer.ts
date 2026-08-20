import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryRegionEntropyDeltaVisualizerTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_region_entropy_delta_visualizer',
    'Generate SVG entropy delta charts tracking entropy shifts, compression changes, and unpacking transitions between snapshots.',
    {
      action: z.enum(['generate_svg_chart', 'get_entropy_shift_points', 'clear_entropy_history']).describe('Entropy visualizer action'),
      address: z.string().optional().describe('Virtual address of memory region to chart'),
      size: z.number().default(0x10000).describe('Byte size of memory region'),
    },
    async ({ action, address, size }) => {
      let data: unknown;
      switch (action) {
        case 'generate_svg_chart':
          data = await httpClient.post('/api/entropy_delta_svg/chart', { address, size });
          break;
        case 'get_entropy_shift_points':
          data = await httpClient.post('/api/entropy_delta_svg/shifts', { address, size });
          break;
        case 'clear_entropy_history':
          data = await httpClient.post('/api/entropy_delta_svg/clear', {});
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
