import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerGdiUserObjectInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_gdi_user_object_inspector',
    'Enumerate Windows USER and GDI objects (HWND, HDC, HBITMAP, HMENU, HICON, HRGN) and detect handle exhaustion or graphic resource leaks.',
    {
      action: z.enum(['list_user_objects', 'list_gdi_objects', 'check_handle_limits', 'diff_objects']).describe('GDI/USER action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'list_user_objects':
          data = await httpClient.get('/api/gdi_user/user_objects');
          break;
        case 'list_gdi_objects':
          data = await httpClient.get('/api/gdi_user/gdi_objects');
          break;
        case 'check_handle_limits':
          data = await httpClient.get('/api/gdi_user/limits');
          break;
        case 'diff_objects':
          data = await httpClient.get('/api/gdi_user/diff');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
