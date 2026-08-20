import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryPermissionWatcherTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_permission_watcher',
    'Track dynamic memory page protection transitions (PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ) via VirtualProtect/NtProtectVirtualMemory hooks.',
    {
      action: z.enum(['list_protection_transitions', 'get_rwx_transitions', 'clear_history']).describe('Permission watcher action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'list_protection_transitions':
          data = await httpClient.get('/api/mem_protect/transitions');
          break;
        case 'get_rwx_transitions':
          data = await httpClient.get('/api/mem_protect/rwx_events');
          break;
        case 'clear_history':
          data = await httpClient.post('/api/mem_protect/clear', {});
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
