import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerEntropyHeatmapTools(server: McpServer) {
  server.tool(
    'x64dbg_entropy_heatmap',
    'Generate high-resolution Shannon entropy heatmaps across module sections and virtual memory ranges (detect packed, compressed, or encrypted buffers).',
    {
      action: z.enum(['scan_module_entropy', 'scan_region_entropy', 'find_high_entropy_blocks']).describe('Entropy analysis action'),
      module: z.string().optional().describe('Target module name'),
      address: z.string().optional().describe('Base address of region to analyze'),
      size: z.number().optional().describe('Size in bytes of region to analyze'),
      block_size: z.number().optional().default(256).describe('Granularity block size in bytes'),
    },
    async ({ action, module, address, size, block_size }) => {
      let data: unknown;
      switch (action) {
        case 'scan_module_entropy':
          data = await httpClient.post('/api/entropy/module', { module, block_size });
          break;
        case 'scan_region_entropy':
          data = await httpClient.post('/api/entropy/region', { address, size, block_size });
          break;
        case 'find_high_entropy_blocks':
          data = await httpClient.post('/api/entropy/high_entropy_blocks', { module, address, size });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
