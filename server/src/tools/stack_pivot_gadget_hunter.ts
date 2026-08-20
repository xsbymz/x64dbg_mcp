import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerStackPivotGadgetHunterTools(server: McpServer) {
  server.tool(
    'x64dbg_stack_pivot_gadget_hunter',
    'Specialized discovery of stack pivot gadgets (xchg rsp, rax; ret, mov rsp, rbx; ret, add rsp, 0x100; ret, push rax; pop rsp; ret).',
    {
      action: z.enum(['find_pivot_gadgets', 'score_pivot_reliability', 'filter_by_register']).describe('Stack pivot action'),
      target_register: z.string().optional().describe('Source register controlled for pivoting (e.g. RAX, RBX, RCX, RDI, RSI)'),
      max_stack_shift: z.number().optional().describe('Maximum displacement shift in bytes (e.g. 0x200)'),
    },
    async ({ action, target_register, max_stack_shift }) => {
      let data: unknown;
      switch (action) {
        case 'find_pivot_gadgets':
          data = await httpClient.post('/api/pivot_hunter/find', { target_register, max_stack_shift });
          break;
        case 'score_pivot_reliability':
          data = await httpClient.post('/api/pivot_hunter/score', { target_register });
          break;
        case 'filter_by_register':
          data = await httpClient.post('/api/pivot_hunter/by_register', { target_register });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
