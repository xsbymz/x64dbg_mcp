import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerNtThreadExecutionStateAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_nt_thread_execution_state_auditor',
    'Audit thread execution power states (SetThreadExecutionState, ES_CONTINUOUS, ES_SYSTEM_REQUIRED, ES_DISPLAY_REQUIRED, ES_AWAYMODE_REQUIRED).',
    {
      action: z.enum(['audit_power_states', 'check_sleep_prevention', 'get_active_power_flags']).describe('Execution state action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'audit_power_states':
          data = await httpClient.get('/api/exec_state/audit');
          break;
        case 'check_sleep_prevention':
          data = await httpClient.get('/api/exec_state/sleep_prevented');
          break;
        case 'get_active_power_flags':
          data = await httpClient.get('/api/exec_state/flags');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
