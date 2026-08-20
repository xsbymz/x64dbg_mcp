import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRopChainDisassemblerTools(server: McpServer) {
  server.tool(
    'x64dbg_rop_chain_disassembler',
    'Disassemble and visualize raw memory buffers containing ROP gadget pointers into an interconnected, linear instruction flow graph.',
    {
      action: z.enum(['disassemble_rop_buffer', 'validate_gadget_chain', 'trace_chain_register_effects']).describe('ROP disasm action'),
      buffer_address: z.string().describe('Address of the ROP gadget array in memory'),
      gadget_count: z.number().optional().describe('Number of gadget pointers to disassemble (default 16)'),
    },
    async ({ action, buffer_address, gadget_count }) => {
      let data: unknown;
      switch (action) {
        case 'disassemble_rop_buffer':
          data = await httpClient.post('/api/rop_disasm/buffer', { buffer_address, gadget_count });
          break;
        case 'validate_gadget_chain':
          data = await httpClient.post('/api/rop_disasm/validate', { buffer_address, gadget_count });
          break;
        case 'trace_chain_register_effects':
          data = await httpClient.post('/api/rop_disasm/effects', { buffer_address, gadget_count });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
