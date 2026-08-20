import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHandleLeakDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_handle_leak_detector',
    'Snapshot and diff open Win32 handle tables over execution intervals to isolate unclosed files, events, sections, or registry key handle leaks.',
    {
      action: z.enum(['snapshot_handles', 'diff_handle_leaks', 'get_growing_handle_types']).describe('Handle leak action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'snapshot_handles':
          data = await httpClient.get('/api/handle_leak/snapshot');
          break;
        case 'diff_handle_leaks':
          data = await httpClient.get('/api/handle_leak/diff');
          break;
        case 'get_growing_handle_types':
          data = await httpClient.get('/api/handle_leak/growing');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
