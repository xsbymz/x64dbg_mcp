import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerProcessMitigationAcgEnforcerCheckerTools(server: McpServer) {
  server.tool(
    'x64dbg_process_mitigation_acg_enforcer_checker',
    'Inspect Arbitrary Code Guard (ACG) and Dynamic Code Policy state on virtual memory allocations to detect ACG bypass vulnerabilities.',
    {
      action: z.enum(['check_acg_status', 'test_dynamic_code_policy', 'list_acg_mitigations']).describe('ACG checker action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'check_acg_status':
          data = await httpClient.get('/api/acg_check/status');
          break;
        case 'test_dynamic_code_policy':
          data = await httpClient.get('/api/acg_check/test');
          break;
        case 'list_acg_mitigations':
          data = await httpClient.get('/api/acg_check/mitigations');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
