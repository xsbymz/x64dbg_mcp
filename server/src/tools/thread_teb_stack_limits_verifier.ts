import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerThreadTebStackLimitsVerifierTools(server: McpServer) {
  server.tool(
    'x64dbg_thread_teb_stack_limits_verifier',
    'Cross-check TEB.StackBase, TEB.StackLimit, and TEB.DeallocationStack against current RSP and detect stack pivot anomalies.',
    {
      action: z.enum(['verify_current_stack', 'get_teb_limits', 'detect_stack_pivot']).describe('Stack limit action'),
      thread_id: z.number().optional().describe('Thread ID (defaults to active thread)'),
    },
    async ({ action, thread_id }) => {
      let data: unknown;
      switch (action) {
        case 'verify_current_stack':
          data = await httpClient.post('/api/teb_stack/verify', { thread_id });
          break;
        case 'get_teb_limits':
          data = await httpClient.post('/api/teb_stack/limits', { thread_id });
          break;
        case 'detect_stack_pivot':
          data = await httpClient.post('/api/teb_stack/pivot_check', { thread_id });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
