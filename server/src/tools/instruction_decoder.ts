import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerInstructionDecoderTools(server: McpServer) {
  server.tool(
    'x64dbg_instruction_decoder',
    'Exhaustively decode machine code hex bytes into structured fields: legacy prefixes, REX prefix, VEX/EVEX prefix, Opcode, ModR/M, SIB, Displacement, and Immediates.',
    {
      action: z.enum(['decode_bytes', 'decode_at_address']).describe('Decoder action'),
      bytes_hex: z.string().optional().describe('Machine code bytes in hex format (e.g. 48 8B 05 34 12 00 00)'),
      address: z.string().optional().describe('Target address in debuggee to decode'),
    },
    async ({ action, bytes_hex, address }) => {
      let data: unknown;
      switch (action) {
        case 'decode_bytes':
          data = await httpClient.post('/api/decoder/bytes', { bytes_hex });
          break;
        case 'decode_at_address':
          data = await httpClient.post('/api/decoder/at_address', { address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
