import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerOleDragDropDataSnifferTools(server: McpServer) {
  server.tool(
    'x64dbg_ole_drag_drop_data_sniffer',
    'Intercept and sniff OLE Drag and Drop IDropTarget, IDropSource, and IDataObject clipboard format buffers in memory.',
    {
      action: z.enum(['sniff_drop_targets', 'extract_data_object_formats', 'get_active_drag_buffer']).describe('OLE sniffer action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'sniff_drop_targets':
          data = await httpClient.get('/api/ole_drag/targets');
          break;
        case 'extract_data_object_formats':
          data = await httpClient.get('/api/ole_drag/formats');
          break;
        case 'get_active_drag_buffer':
          data = await httpClient.get('/api/ole_drag/buffer');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
