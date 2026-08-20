import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAppcontainerLoopbackPermissionCheckerTools(server: McpServer) {
  server.tool(
    'x64dbg_appcontainer_loopback_permission_checker',
    'Check AppContainer network loopback exemption permissions, loopback firewall rules, and container isolation boundaries.',
    {
      action: z.enum(['check_loopback_exemption', 'list_loopback_exempt_containers', 'get_network_isolation_flags']).describe('Loopback checker action'),
      package_sid: z.string().optional().describe('AppContainer Package SID string'),
    },
    async ({ action, package_sid }) => {
      let data: unknown;
      switch (action) {
        case 'check_loopback_exemption':
          data = await httpClient.post('/api/loopback_check/check', { package_sid });
          break;
        case 'list_loopback_exempt_containers':
          data = await httpClient.get('/api/loopback_check/list');
          break;
        case 'get_network_isolation_flags':
          data = await httpClient.post('/api/loopback_check/flags', { package_sid });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
