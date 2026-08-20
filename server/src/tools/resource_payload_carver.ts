import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerResourcePayloadCarverTools(server: McpServer) {
  server.tool(
    'x64dbg_resource_payload_carver',
    'Exhaustively extract and carve embedded PE, RCDATA, HTML, and binary payloads stored inside Windows PE resources (.rsrc).',
    {
      action: z.enum(['list_all_resources', 'carve_resource_by_id', 'detect_embedded_pe_in_resources']).describe('Resource carving action'),
      module: z.string().optional().describe('Target module name'),
      resource_type: z.string().optional().describe('Resource type (e.g. RCDATA, RT_RCDATA, 10)'),
      resource_name: z.string().optional().describe('Resource ID or name string'),
      output_path: z.string().optional().describe('Target file path to write carved payload'),
    },
    async ({ action, module, resource_type, resource_name, output_path }) => {
      let data: unknown;
      switch (action) {
        case 'list_all_resources':
          data = await httpClient.post('/api/rsrc_carver/list', { module });
          break;
        case 'carve_resource_by_id':
          data = await httpClient.post('/api/rsrc_carver/carve', { module, resource_type, resource_name, output_path });
          break;
        case 'detect_embedded_pe_in_resources':
          data = await httpClient.post('/api/rsrc_carver/detect_pe', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
