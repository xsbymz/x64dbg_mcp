import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryProtectionTransitionLoggerTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_protection_transition_logger',
    'Real-time logging and auditing of all VirtualProtectEx and NtProtectVirtualMemory memory protection transitions with calling stack traces.',
    {
      action: z.enum(['list_transitions', 'filter_rwx_transitions', 'clear_transition_log']).describe('Protection logger action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'list_transitions':
          data = await httpClient.get('/api/prot_log/list');
          break;
        case 'filter_rwx_transitions':
          data = await httpClient.get('/api/prot_log/rwx');
          break;
        case 'clear_transition_log':
          data = await httpClient.post('/api/prot_log/clear', {});
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
