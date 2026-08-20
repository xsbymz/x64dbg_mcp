import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAslrEntropyEvaluatorTools(server: McpServer) {
  server.tool(
    'x64dbg_aslr_entropy_evaluator',
    'Measure the effective high-entropy ASLR distribution across loaded image base addresses, heap allocations, and stack base pointers.',
    {
      action: z.enum(['evaluate_aslr_entropy', 'check_high_entropy_aslr', 'get_module_base_deltas']).describe('ASLR evaluator action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'evaluate_aslr_entropy':
          data = await httpClient.get('/api/aslr_eval/entropy');
          break;
        case 'check_high_entropy_aslr':
          data = await httpClient.get('/api/aslr_eval/high_entropy');
          break;
        case 'get_module_base_deltas':
          data = await httpClient.get('/api/aslr_eval/deltas');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
