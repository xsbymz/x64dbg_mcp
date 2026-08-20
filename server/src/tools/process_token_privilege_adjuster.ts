import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerProcessTokenPrivilegeAdjusterTools(server: McpServer) {
  server.tool(
    'x64dbg_process_token_privilege_adjuster',
    'Enable or disable target process token privileges (SeDebugPrivilege, SeAssignPrimaryTokenPrivilege, SeTcbPrivilege).',
    {
      action: z.enum(['enable_privilege', 'disable_privilege', 'list_all_privileges']).describe('Token privilege action'),
      privilege_name: z.string().optional().describe('Privilege name (e.g., SeDebugPrivilege)'),
    },
    async ({ action, privilege_name }) => {
      let data: unknown;
      switch (action) {
        case 'enable_privilege':
          data = await httpClient.post('/api/token_adjust/enable', { privilege_name });
          break;
        case 'disable_privilege':
          data = await httpClient.post('/api/token_adjust/disable', { privilege_name });
          break;
        case 'list_all_privileges':
          data = await httpClient.get('/api/token_adjust/list');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
