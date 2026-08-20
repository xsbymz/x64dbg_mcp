import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerComClassObjectRotTableInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_com_class_object_rot_table_inspector',
    'Inspect COM Running Object Table (ROT) registrations, active IMoniker display names, and moniker binding contexts.',
    {
      action: z.enum(['enum_rot_objects', 'get_moniker_display_name', 'inspect_binding_context']).describe('ROT action'),
      rot_cookie: z.number().optional().describe('ROT registration cookie ID'),
    },
    async ({ action, rot_cookie }) => {
      let data: unknown;
      switch (action) {
        case 'enum_rot_objects':
          data = await httpClient.get('/api/rot_table/enum');
          break;
        case 'get_moniker_display_name':
          data = await httpClient.post('/api/rot_table/name', { rot_cookie });
          break;
        case 'inspect_binding_context':
          data = await httpClient.post('/api/rot_table/context', { rot_cookie });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
