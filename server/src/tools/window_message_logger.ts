import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWindowMessageLoggerTools(server: McpServer) {
  server.tool(
    'x64dbg_window_message_logger',
    'Hook and decode Win32 window messages (WndProc): log WM_COMMAND, WM_NOTIFY, WM_KEYDOWN, WM_COPYDATA, and custom inter-process window messages.',
    {
      action: z.enum(['list_logged_messages', 'filter_by_message_id', 'clear_message_log']).describe('Window message action'),
      msg_id: z.string().optional().describe('Filter by Windows message ID (e.g. WM_COMMAND, 0x0111)'),
    },
    async ({ action, msg_id }) => {
      let data: unknown;
      switch (action) {
        case 'list_logged_messages':
          data = await httpClient.get('/api/wndproc/messages');
          break;
        case 'filter_by_message_id':
          data = await httpClient.post('/api/wndproc/filter', { msg_id });
          break;
        case 'clear_message_log':
          data = await httpClient.post('/api/wndproc/clear', {});
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
