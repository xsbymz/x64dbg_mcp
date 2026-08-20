import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerComMonikersInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_com_monikers_inspector',
    'Parse and inspect COM Monikers (IMoniker, File Monikers, Item Monikers, Composite Monikers, and scriptlet/URL monikers) used in COM activation.',
    {
      action: z.enum(['parse_display_name', 'list_registered_monikers', 'inspect_running_object_table']).describe('COM Moniker action'),
      display_name: z.string().optional().describe('Moniker display name string to parse (e.g. script:http://...)'),
    },
    async ({ action, display_name }) => {
      let data: unknown;
      switch (action) {
        case 'parse_display_name':
          data = await httpClient.post('/api/com_moniker/parse', { display_name });
          break;
        case 'list_registered_monikers':
          data = await httpClient.get('/api/com_moniker/registered');
          break;
        case 'inspect_running_object_table':
          data = await httpClient.get('/api/com_moniker/rot');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
