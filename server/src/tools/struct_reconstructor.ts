import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerStructReconstructorTools(server: McpServer) {
  server.tool(
    'x64dbg_struct_reconstructor',
    'Reconstruct C/C++ struct definitions, field offsets, and types automatically by analyzing register displacement memory accesses in disassembled functions.',
    {
      action: z.enum(['reconstruct', 'infer_types', 'export_header']).describe('Struct reconstruction action'),
      address: z.string().describe('Function address or start address of inspection'),
      base_register: z.enum(['rcx', 'rdx', 'r8', 'r9', 'rax', 'rbx', 'rsi', 'rdi', 'rbp', 'rsp']).optional().default('rcx').describe('Register holding struct pointer'),
      struct_name: z.string().optional().default('SynthesizedStruct'),
    },
    async ({ action, address, base_register, struct_name }) => {
      let data: unknown;
      switch (action) {
        case 'reconstruct':
          data = await httpClient.post('/api/struct/reconstruct', { address, base_register, struct_name });
          break;
        case 'infer_types':
          data = await httpClient.post('/api/struct/infer_types', { address, base_register });
          break;
        case 'export_header':
          data = await httpClient.post('/api/struct/export_header', { address, base_register, struct_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
