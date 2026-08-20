import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryRegionAliasingDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_region_aliasing_detector',
    'Detect overlapping virtual memory mappings, shared section views (MapViewOfSection), Copy-On-Write (COW) page aliasing, and memory mirroring.',
    {
      action: z.enum(['scan_aliased_regions', 'check_section_views', 'detect_cow_pages']).describe('Aliasing action'),
      address: z.string().optional().describe('Base address to check'),
    },
    async ({ action, address }) => {
      let data: unknown;
      switch (action) {
        case 'scan_aliased_regions':
          data = await httpClient.post('/api/mem_alias/scan', { address });
          break;
        case 'check_section_views':
          data = await httpClient.get('/api/mem_alias/section_views');
          break;
        case 'detect_cow_pages':
          data = await httpClient.post('/api/mem_alias/cow_pages', { address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
