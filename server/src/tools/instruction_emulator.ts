import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerInstructionEmulatorTools(server: McpServer) {
  server.tool(
    'x64dbg_instruction_emulator',
    'Static x86-64 instruction emulation and execution tracing. Execute instructions without modifying process state to analyze behavior. ' +
    'Actions: emulate_single (single instruction), emulate_range (sequence of instructions), trace_execution (step-by-step with side effects).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('emulate_single'),
          address: z.string().describe('Instruction address (hex or expression)'),
          show_operands: z.boolean().optional().default(true).describe('Show decoded operands'),
          show_side_effects: z.boolean().optional().default(true).describe('Show predicted register/memory changes')
        }),
        z.object({
          action: z.literal('emulate_range'),
          start: z.string().describe('Start address'),
          end: z.string().describe('End address (or count of instructions)'),
          count: z.boolean().optional().default(false).describe('If true, end is instruction count'),
          max_steps: z.number().optional().default(100).describe('Max instructions to emulate')
        }),
        z.object({
          action: z.literal('trace_execution'),
          address: z.string().describe('Starting address'),
          breakpoint_condition: z.string().optional().describe('Condition to stop emulation (e.g., "rax == 0")'),
          max_steps: z.number().optional().default(50).describe('Max steps before stopping'),
          capture_memory: z.boolean().optional().default(false).describe('Capture memory reads/writes')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'emulate_single':
            data = await httpClient.post('/api/emulator/single', {
              address: action.address,
              show_operands: action.show_operands,
              show_side_effects: action.show_side_effects
            });
            break;
          case 'emulate_range':
            data = await httpClient.post('/api/emulator/range', {
              start: action.start,
              end: action.end,
              count: action.count,
              max_steps: action.max_steps
            });
            break;
          case 'trace_execution':
            data = await httpClient.post('/api/emulator/trace', {
              address: action.address,
              breakpoint_condition: action.breakpoint_condition,
              max_steps: action.max_steps,
              capture_memory: action.capture_memory
            });
            break;
        }
        
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
