import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerIpcMonitorTools(server: McpServer) {
  server.tool(
    'x64dbg_ipc_monitor',
    'Inter-Process Communication (IPC) monitor: enumerates Named Pipes, Mailslots, Shared Memory Sections (FileMapping), and active IPC endpoints used by the target process.',
    {
      action: z.enum(['list_named_pipes', 'list_mailslots', 'list_shared_sections', 'dump_ipc_activity']).describe('IPC query action'),
      filter_name: z.string().optional().describe('Optional name filter for IPC objects'),
    },
    async ({ action, filter_name }) => {
      let data: unknown;
      switch (action) {
        case 'list_named_pipes':
          data = await httpClient.get('/api/ipc/named_pipes', filter_name ? { filter: filter_name } : undefined);
          break;
        case 'list_mailslots':
          data = await httpClient.get('/api/ipc/mailslots');
          break;
        case 'list_shared_sections':
          data = await httpClient.get('/api/ipc/shared_sections');
          break;
        case 'dump_ipc_activity':
          data = await httpClient.post('/api/ipc/activity_log', { filter_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
