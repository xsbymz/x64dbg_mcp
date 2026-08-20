import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAppcontainerCapabilityCheckerTools(server: McpServer) {
  server.tool(
    'x64dbg_appcontainer_capability_checker',
    'Check AppContainer token capability SIDs against standard Windows capability namespaces (internetClient, privateNetworkClientServer, documentsLibrary, enterpriseAuthentication).',
    {
      action: z.enum(['check_capabilities', 'resolve_known_capability_sids', 'audit_sandbox_boundary']).describe('Capability checker action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'check_capabilities':
          data = await httpClient.get('/api/appcontainer_cap/check');
          break;
        case 'resolve_known_capability_sids':
          data = await httpClient.get('/api/appcontainer_cap/sids');
          break;
        case 'audit_sandbox_boundary':
          data = await httpClient.get('/api/appcontainer_cap/boundary');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
