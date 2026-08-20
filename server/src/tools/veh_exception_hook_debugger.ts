import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerVehExceptionHookDebuggerTools(server: McpServer) {
  server.tool(
    'x64dbg_veh_exception_hook_debugger',
    'Hook and log all Vectored Exception Handler (VEH) invocations with exception pointers, exception codes, faulting addresses, and handler return codes.',
    {
      action: z.enum(['list_veh_invocations', 'filter_by_exception_code', 'clear_veh_invocation_logs']).describe('VEH hook debugger action'),
      exception_code: z.string().optional().describe('Exception hex code to filter (e.g. 0xC0000005)'),
    },
    async ({ action, exception_code }) => {
      let data: unknown;
      switch (action) {
        case 'list_veh_invocations':
          data = await httpClient.get('/api/veh_hook/invocations');
          break;
        case 'filter_by_exception_code':
          data = await httpClient.post('/api/veh_hook/filter', { exception_code });
          break;
        case 'clear_veh_invocation_logs':
          data = await httpClient.post('/api/veh_hook/clear');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
