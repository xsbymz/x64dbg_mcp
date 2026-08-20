import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWin32WindowPropInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_win32_window_prop_inspector',
    'Enumerate Win32 window properties (GetPropW, EnumPropsExW) across top-level HWNDs to detect subclassing and hidden data.',
    {
      action: z.enum(['enum_window_props', 'get_prop_value', 'list_all_windows_with_props']).describe('Window property action'),
      hwnd: z.number().optional().describe('Window handle (HWND) integer value'),
      prop_name: z.string().optional().describe('Property atom name string'),
    },
    async ({ action, hwnd, prop_name }) => {
      let data: unknown;
      switch (action) {
        case 'enum_window_props':
          data = await httpClient.post('/api/wnd_props/enum', { hwnd });
          break;
        case 'get_prop_value':
          data = await httpClient.post('/api/wnd_props/get', { hwnd, prop_name });
          break;
        case 'list_all_windows_with_props':
          data = await httpClient.get('/api/wnd_props/all');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
