import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerServiceInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_service_inspector',
    'Inspect Windows Services created, started, or queried by debuggee: query Service Control Manager (SCM), inspect service binary paths, accounts (LocalSystem/NetworkService), and DLL hosting stubs (svchost).',
    {
      action: z.enum(['list_active_services', 'inspect_service', 'check_unquoted_paths', 'get_service_permissions']).describe('Service inspection action'),
      service_name: z.string().optional().describe('Service short name or display name'),
    },
    async ({ action, service_name }) => {
      let data: unknown;
      switch (action) {
        case 'list_active_services':
          data = await httpClient.get('/api/service/list');
          break;
        case 'inspect_service':
          data = await httpClient.post('/api/service/inspect', { service_name });
          break;
        case 'check_unquoted_paths':
          data = await httpClient.get('/api/service/unquoted_paths');
          break;
        case 'get_service_permissions':
          data = await httpClient.post('/api/service/permissions', { service_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
