import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerComSurrogateDcomInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_com_surrogate_dcom_inspector',
    'Audit DCOM / dllhost.exe COM Surrogate processes, AppIDs, RunAs authentication credentials, and remote activation security permissions.',
    {
      action: z.enum(['list_surrogate_processes', 'audit_appid_permissions', 'inspect_dcom_endpoints']).describe('DCOM/Surrogate action'),
      appid: z.string().optional().describe('AppID GUID to inspect permissions for'),
    },
    async ({ action, appid }) => {
      let data: unknown;
      switch (action) {
        case 'list_surrogate_processes':
          data = await httpClient.get('/api/dcom_surrogate/processes');
          break;
        case 'audit_appid_permissions':
          data = await httpClient.post('/api/dcom_surrogate/appid_permissions', { appid });
          break;
        case 'inspect_dcom_endpoints':
          data = await httpClient.get('/api/dcom_surrogate/endpoints');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
