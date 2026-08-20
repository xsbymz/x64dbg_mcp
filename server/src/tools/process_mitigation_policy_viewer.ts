import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerProcessMitigationPolicyViewerTools(server: McpServer) {
  server.tool(
    'x64dbg_process_mitigation_policy_viewer',
    'Query Windows Exploit Guard mitigation policies (GetProcessMitigationPolicy): ASLR, DEP, CFG, ACG (Arbitrary Code Guard), CET User Shadow Stacks, and Child Process Policies.',
    {
      action: z.enum(['query_all_mitigations', 'check_acg_status', 'check_shadow_stack_policy']).describe('Mitigation policy action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'query_all_mitigations':
          data = await httpClient.get('/api/mitigations/all');
          break;
        case 'check_acg_status':
          data = await httpClient.get('/api/mitigations/acg');
          break;
        case 'check_shadow_stack_policy':
          data = await httpClient.get('/api/mitigations/shadow_stack');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
