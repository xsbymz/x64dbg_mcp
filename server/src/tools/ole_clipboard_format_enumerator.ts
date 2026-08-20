import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerOleClipboardFormatEnumeratorTools(server: McpServer) {
  server.tool(
    'x64dbg_ole_clipboard_format_enumerator',
    'Enumerate all registered and synthetic OLE clipboard formats, FORMATETC descriptors, and STGMEDIUM data handles.',
    {
      action: z.enum(['enum_formats', 'get_format_name', 'inspect_medium']).describe('OLE clipboard action'),
      format_id: z.number().optional().describe('Clipboard format integer ID'),
      medium_ptr: z.string().optional().describe('Virtual address of STGMEDIUM structure'),
    },
    async ({ action, format_id, medium_ptr }) => {
      let data: unknown;
      switch (action) {
        case 'enum_formats':
          data = await httpClient.get('/api/ole_clip/formats');
          break;
        case 'get_format_name':
          data = await httpClient.post('/api/ole_clip/name', { format_id });
          break;
        case 'inspect_medium':
          data = await httpClient.post('/api/ole_clip/medium', { medium_ptr });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
