import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerGdiDcAttributeInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_gdi_dc_attribute_inspector',
    'Inspect GDI Device Context (HDC) attributes: selected font, pen, brush, clipping region, map mode, and viewport origins.',
    {
      action: z.enum(['inspect_hdc', 'list_selected_objects', 'get_clipping_bounds']).describe('HDC inspector action'),
      hdc: z.number().describe('GDI Device Context handle (HDC) integer value'),
    },
    async ({ action, hdc }) => {
      let data: unknown;
      switch (action) {
        case 'inspect_hdc':
          data = await httpClient.post('/api/gdi_dc/inspect', { hdc });
          break;
        case 'list_selected_objects':
          data = await httpClient.post('/api/gdi_dc/objects', { hdc });
          break;
        case 'get_clipping_bounds':
          data = await httpClient.post('/api/gdi_dc/clipping', { hdc });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
