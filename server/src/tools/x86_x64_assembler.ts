import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerX86X64AssemblerTools(server: McpServer) {
  server.tool(
    'x64dbg_x86_x64_assembler',
    'Assemble raw x86/x64 assembly instruction text into machine code bytes with custom base address origin (supports multi-line assembly scripts).',
    {
      action: z.enum(['assemble_instruction', 'assemble_block']).describe('Assembler action'),
      instruction: z.string().describe('Assembly instruction or multi-line block (e.g. mov rax, [rcx+8])'),
      base_address: z.string().optional().describe('Origin virtual address for relative jump/call displacement calculation'),
    },
    async ({ action, instruction, base_address }) => {
      let data: unknown;
      switch (action) {
        case 'assemble_instruction':
          data = await httpClient.post('/api/assembler/instruction', { instruction, base_address });
          break;
        case 'assemble_block':
          data = await httpClient.post('/api/assembler/block', { instruction, base_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}

