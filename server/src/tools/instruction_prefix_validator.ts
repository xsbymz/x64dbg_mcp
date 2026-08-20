import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerInstructionPrefixValidatorTools(server: McpServer) {
  server.tool(
    'x64dbg_instruction_prefix_validator',
    'Validate x86/x64 instruction prefix combinations and detect redundant, illegal, or anti-disassembler prefix spam (LOCK, REPNZ, multiple REX, operand size 0x66 spam).',
    {
      action: z.enum(['validate_prefixes', 'detect_prefix_spam', 'decode_effective_prefix_chain']).describe('Prefix validator action'),
      address: z.string().describe('Address of the instruction in memory'),
    },
    async ({ action, address }) => {
      let data: unknown;
      switch (action) {
        case 'validate_prefixes':
          data = await httpClient.post('/api/prefix_val/validate', { address });
          break;
        case 'detect_prefix_spam':
          data = await httpClient.post('/api/prefix_val/spam', { address });
          break;
        case 'decode_effective_prefix_chain':
          data = await httpClient.post('/api/prefix_val/chain', { address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
