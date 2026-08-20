import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryCommitTrackerTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_commit_tracker',
    'Track dynamic memory commitment (VirtualAlloc MEM_COMMIT vs MEM_RESERVE, WorkingSetSize, PagefileUsage, PrivateBytes) and peak commit limits.',
    {
      action: z.enum(['get_process_memory_counters', 'track_commit_growth', 'list_committed_ranges']).describe('Memory commit action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'get_process_memory_counters':
          data = await httpClient.get('/api/mem_commit/counters');
          break;
        case 'track_commit_growth':
          data = await httpClient.get('/api/mem_commit/growth');
          break;
        case 'list_committed_ranges':
          data = await httpClient.get('/api/mem_commit/ranges');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
