import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerTokenPrivilegeAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_token_privilege_auditor',
    'Audit Windows access tokens: query integrity levels, enumerate privileges (SeDebug, SeImpersonate, SeTcb, SeBackup), list group SIDs, and inspect restricted tokens.',
    {
      action: z.enum(['query_process_token', 'query_thread_token', 'list_privileges', 'check_privilege_escalation']).describe('Token audit action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'query_process_token':
          data = await httpClient.get('/api/token/process');
          break;
        case 'query_thread_token':
          data = await httpClient.get('/api/token/thread');
          break;
        case 'list_privileges':
          data = await httpClient.get('/api/token/privileges');
          break;
        case 'check_privilege_escalation':
          data = await httpClient.get('/api/token/escalation_check');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
