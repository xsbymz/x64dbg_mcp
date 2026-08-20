import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerExceptionFilterTesterTools(server: McpServer) {
  server.tool(
    'x64dbg_exception_filter_tester',
    'Inject synthetic software exceptions (e.g. STATUS_INTEGER_DIVIDE_BY_ZERO, STATUS_GUARD_PAGE_VIOLATION, STATUS_PRIVILEGED_INSTRUCTION) to test target filter handling and debugger hooks.',
    {
      action: z.enum(['simulate_exception', 'list_exception_codes']).describe('Exception test action'),
      exception_code: z.string().optional().describe('Exception hex code (e.g. 0xC0000005, 0xC0000094)'),
    },
    async ({ action, exception_code }) => {
      let data: unknown;
      switch (action) {
        case 'simulate_exception':
          data = await httpClient.post('/api/exception_tester/simulate', { exception_code });
          break;
        case 'list_exception_codes':
          data = await httpClient.get('/api/exception_tester/codes');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
