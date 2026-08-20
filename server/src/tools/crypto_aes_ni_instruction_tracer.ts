import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCryptoAesNiInstructionTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_crypto_aes_ni_instruction_tracer',
    'Trace hardware AES-NI instructions (AESENC, AESENCLAST, AESDEC, AESDECLAST, AESKEYGENASSIST) during dynamic execution.',
    {
      action: z.enum(['trace_aesni_calls', 'get_aesni_round_keys', 'detect_aesni_loops']).describe('AES-NI tracer action'),
      max_events: z.number().default(64).describe('Maximum AES-NI instruction events to capture'),
    },
    async ({ action, max_events }) => {
      let data: unknown;
      switch (action) {
        case 'trace_aesni_calls':
          data = await httpClient.post('/api/aesni_trace/trace', { max_events });
          break;
        case 'get_aesni_round_keys':
          data = await httpClient.get('/api/aesni_trace/keys');
          break;
        case 'detect_aesni_loops':
          data = await httpClient.get('/api/aesni_trace/loops');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
