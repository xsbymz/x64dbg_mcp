import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerGdiFontResourceCarverTools(server: McpServer) {
  server.tool(
    'x64dbg_gdi_font_resource_carver',
    'Carve embedded TrueType (TTF), OpenType (OTF), and Windows FON raster font resources from virtual memory buffers.',
    {
      action: z.enum(['scan_embedded_fonts', 'extract_ttf_header', 'dump_font_table']).describe('Font carver action'),
      address: z.string().optional().describe('Address of the font buffer (TrueType sfnt magic 0x00010000 or OTTO)'),
    },
    async ({ action, address }) => {
      let data: unknown;
      switch (action) {
        case 'scan_embedded_fonts':
          data = await httpClient.get('/api/font_carve/scan');
          break;
        case 'extract_ttf_header':
          data = await httpClient.post('/api/font_carve/header', { address });
          break;
        case 'dump_font_table':
          data = await httpClient.post('/api/font_carve/table', { address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
