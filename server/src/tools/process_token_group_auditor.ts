import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerProcessTokenGroupAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_process_token_group_auditor',
    'Deep audit of Windows security token groups (TOKEN_GROUPS), SID attributes (SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY, SE_GROUP_INTEGRITY), and restricted SIDs.',
    {
      action: z.enum(['audit_token_groups', 'list_deny_only_sids', 'check_integrity_level_sid']).describe('Token group action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'audit_token_groups':
          data = await httpClient.get('/api/token_group/audit');
          break;
        case 'list_deny_only_sids':
          data = await httpClient.get('/api/token_group/deny_only');
          break;
        case 'check_integrity_level_sid':
          data = await httpClient.get('/api/token_group/integrity');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
