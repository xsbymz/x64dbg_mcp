import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAppcontainerIsolationAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_appcontainer_isolation_auditor',
    'Audit Windows AppContainer sandbox boundaries, LowBox token attributes, package family SIDs, and capability SIDs.',
    {
      action: z.enum(['audit_appcontainer_token', 'list_capabilities', 'check_named_object_paths']).describe('AppContainer action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'audit_appcontainer_token':
          data = await httpClient.get('/api/appcontainer/token');
          break;
        case 'list_capabilities':
          data = await httpClient.get('/api/appcontainer/capabilities');
          break;
        case 'check_named_object_paths':
          data = await httpClient.get('/api/appcontainer/named_objects');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
