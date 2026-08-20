import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerVirtualMemoryCoalescingAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_virtual_memory_coalescing_analyzer',
    'Analyze contiguous free and committed memory regions to detect heap fragmentation and Virtual Memory Manager (VMM) coalescing anomalies.',
    {
      action: z.enum(['analyze_coalescing', 'get_fragmentation_ratio', 'find_largest_free_block']).describe('Coalescing action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'analyze_coalescing':
          data = await httpClient.get('/api/mem_coalesce/analyze');
          break;
        case 'get_fragmentation_ratio':
          data = await httpClient.get('/api/mem_coalesce/fragmentation');
          break;
        case 'find_largest_free_block':
          data = await httpClient.get('/api/mem_coalesce/largest_free');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
