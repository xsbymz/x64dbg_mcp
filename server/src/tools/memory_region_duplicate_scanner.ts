import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryRegionDuplicateScannerTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_region_duplicate_scanner',
    'Scan for duplicate memory blocks across the process virtual address space using fast non-cryptographic hashing (XXH64/Murmur3) to find memory bloat or cloned buffers.',
    {
      action: z.enum(['scan_duplicates', 'list_duplicate_clusters', 'get_memory_redundancy_ratio']).describe('Duplicate scanner action'),
      min_size: z.number().optional().describe('Minimum buffer size to match (default 4096)'),
    },
    async ({ action, min_size }) => {
      let data: unknown;
      switch (action) {
        case 'scan_duplicates':
          data = await httpClient.post('/api/mem_dup/scan', { min_size });
          break;
        case 'list_duplicate_clusters':
          data = await httpClient.get('/api/mem_dup/clusters');
          break;
        case 'get_memory_redundancy_ratio':
          data = await httpClient.get('/api/mem_dup/ratio');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
