import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerStackUnwindCodeDisassemblerTools(server: McpServer) {
  server.tool(
    'x64dbg_stack_unwind_code_disassembler',
    'Disassemble x64 UNWIND_CODE entries (UWOP_PUSH_NONVOL, UWOP_ALLOC_LARGE, UWOP_SAVE_NONVOL, UWOP_SAVE_XMM128, UWOP_PUSH_MACHFRAME) into human-readable prologue stack layouts.',
    {
      action: z.enum(['disassemble_unwind_codes', 'simulate_prologue_stack', 'get_frame_register']).describe('Unwind disasm action'),
      address: z.string().describe('Address of the function or UNWIND_INFO structure'),
    },
    async ({ action, address }) => {
      let data: unknown;
      switch (action) {
        case 'disassemble_unwind_codes':
          data = await httpClient.post('/api/unwind_disasm/codes', { address });
          break;
        case 'simulate_prologue_stack':
          data = await httpClient.post('/api/unwind_disasm/simulate', { address });
          break;
        case 'get_frame_register':
          data = await httpClient.post('/api/unwind_disasm/frame_reg', { address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
