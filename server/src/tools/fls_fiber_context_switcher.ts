import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFlsFiberContextSwitcherTools(server: McpServer) {
  server.tool(
    'x64dbg_fls_fiber_context_switcher',
    'Switch or inspect active Fiber execution contexts, fiber state blocks, and fiber parameter data.',
    {
      action: z.enum(['get_current_fiber', 'list_fibers_in_thread', 'inspect_fiber_context']).describe('Fiber context action'),
      fiber_ptr: z.string().optional().describe('Virtual address of fiber execution context block'),
      thread_id: z.number().optional().describe('Thread ID (defaults to active thread)'),
    },
    async ({ action, fiber_ptr, thread_id }) => {
      let data: unknown;
      switch (action) {
        case 'get_current_fiber':
          data = await httpClient.post('/api/fiber_switch/current', { thread_id });
          break;
        case 'list_fibers_in_thread':
          data = await httpClient.post('/api/fiber_switch/list', { thread_id });
          break;
        case 'inspect_fiber_context':
          data = await httpClient.post('/api/fiber_switch/inspect', { fiber_ptr });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
