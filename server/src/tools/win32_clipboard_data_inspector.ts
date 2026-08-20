import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWin32ClipboardDataInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_win32_clipboard_data_inspector',
    'Inspect Win32 clipboard memory formats (CF_TEXT, CF_UNICODETEXT, CF_HDROP, custom registered formats), sequence numbers, and owner handles.',
    {
      action: z.enum(['enum_formats', 'get_clipboard_owner', 'read_clipboard_text', 'get_sequence_number']).describe('Clipboard action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'enum_formats':
          data = await httpClient.get('/api/clipboard/formats');
          break;
        case 'get_clipboard_owner':
          data = await httpClient.get('/api/clipboard/owner');
          break;
        case 'read_clipboard_text':
          data = await httpClient.get('/api/clipboard/text');
          break;
        case 'get_sequence_number':
          data = await httpClient.get('/api/clipboard/sequence');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
