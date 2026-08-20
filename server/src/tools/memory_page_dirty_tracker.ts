import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryPageDirtyTrackerTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_page_dirty_tracker',
    'Use Windows soft dirty page tracking (GetWriteWatch, MEM_WRITE_WATCH) to record and reset all pages written to between execution checkpoints.',
    {
      action: z.enum(['get_dirty_pages', 'reset_write_watch', 'count_written_pages']).describe('Dirty tracker action'),
      base_address: z.string().optional().describe('Base address of the write-watch memory region'),
      size: z.number().optional().describe('Region size in bytes'),
    },
    async ({ action, base_address, size }) => {
      let data: unknown;
      switch (action) {
        case 'get_dirty_pages':
          data = await httpClient.post('/api/dirty_pages/get', { base_address, size });
          break;
        case 'reset_write_watch':
          data = await httpClient.post('/api/dirty_pages/reset', { base_address, size });
          break;
        case 'count_written_pages':
          data = await httpClient.post('/api/dirty_pages/count', { base_address, size });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
