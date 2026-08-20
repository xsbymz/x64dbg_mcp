import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryWorkingSetDifferTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_working_set_differ',
    'Snapshot and diff the process physical working set page list (QueryWorkingSetEx) over time to locate working set inflation.',
    {
      action: z.enum(['take_snapshot', 'diff_snapshots', 'list_working_set_pages']).describe('Working set action'),
      snapshot_id: z.string().optional().describe('Snapshot identifier'),
    },
    async ({ action, snapshot_id }) => {
      let data: unknown;
      switch (action) {
        case 'take_snapshot':
          data = await httpClient.post('/api/working_set/snapshot', {});
          break;
        case 'diff_snapshots':
          data = await httpClient.post('/api/working_set/diff', { snapshot_id });
          break;
        case 'list_working_set_pages':
          data = await httpClient.get('/api/working_set/pages');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
