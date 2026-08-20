import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerInstructionSideEffectCheckerTools(server: McpServer) {
  server.tool(
    'x64dbg_instruction_side_effect_checker',
    'Predict architectural EFLAGS modifications, register mutations, and memory writes of an instruction prior to execution.',
    {
      action: z.enum(['predict_side_effects', 'check_eflags_clobber', 'check_stack_displacement']).describe('Side effect checker action'),
      instruction_bytes: z.string().optional().describe('Machine code bytes in hex'),
      address: z.string().optional().describe('Virtual address of instruction (uses RIP if omitted)'),
    },
    async ({ action, instruction_bytes, address }) => {
      let data: unknown;
      switch (action) {
        case 'predict_side_effects':
          data = await httpClient.post('/api/inst_side_effects/predict', { instruction_bytes, address });
          break;
        case 'check_eflags_clobber':
          data = await httpClient.post('/api/inst_side_effects/flags', { instruction_bytes, address });
          break;
        case 'check_stack_displacement':
          data = await httpClient.post('/api/inst_side_effects/stack', { instruction_bytes, address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
