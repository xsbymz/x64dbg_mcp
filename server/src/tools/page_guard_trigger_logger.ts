import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPageGuardTriggerLoggerTools(server: McpServer) {
  server.tool(
    'x64dbg_page_guard_trigger_logger',
    'Track PAGE_GUARD exception triggers (STATUS_GUARD_PAGE_VIOLATION), guard page memory access events, and stealth memory read traps.',
    {
      action: z.enum(['list_guard_violations', 'arm_page_guard_trap', 'clear_guard_logs']).describe('Page Guard action'),
      page_address: z.string().optional().describe('Virtual address of page to set PAGE_GUARD on'),
    },
    async ({ action, page_address }) => {
      let data: unknown;
      switch (action) {
        case 'list_guard_violations':
          data = await httpClient.get('/api/page_guard/violations');
          break;
        case 'arm_page_guard_trap':
          data = await httpClient.post('/api/page_guard/arm', { page_address });
          break;
        case 'clear_guard_logs':
          data = await httpClient.post('/api/page_guard/clear');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
