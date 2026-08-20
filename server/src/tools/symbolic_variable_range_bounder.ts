import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSymbolicVariableRangeBounderTools(server: McpServer) {
  server.tool(
    'x64dbg_symbolic_variable_range_bounder',
    'Compute interval domain bounds [min, max] for symbolic variables and registers along an execution path via SMT/Z3 range queries.',
    {
      action: z.enum(['bound_variable', 'bound_all_registers', 'check_integer_overflow_potential']).describe('Range bound action'),
      variable_name: z.string().optional().describe('Symbolic variable name (e.g. rax_0, buffer_len)'),
      register_name: z.string().optional().describe('Register name to bound (e.g. RAX, RBX)'),
    },
    async ({ action, variable_name, register_name }) => {
      let data: unknown;
      switch (action) {
        case 'bound_variable':
          data = await httpClient.post('/api/range_bounds/var', { variable_name });
          break;
        case 'bound_all_registers':
          data = await httpClient.get('/api/range_bounds/registers');
          break;
        case 'check_integer_overflow_potential':
          data = await httpClient.post('/api/range_bounds/overflow', { register_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
