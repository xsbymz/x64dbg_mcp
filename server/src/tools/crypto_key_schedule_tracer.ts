import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCryptoKeyScheduleTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_crypto_key_schedule_tracer',
    'Trace AES-128/AES-256 and DES key expansion schedules (AES round keys, Rijndael key schedules) generated in heap or stack buffers.',
    {
      action: z.enum(['trace_aes_key_schedule', 'scan_for_round_keys', 'validate_key_expansion']).describe('Key schedule action'),
      buffer_address: z.string().optional().describe('Virtual address of suspected round key buffer'),
    },
    async ({ action, buffer_address }) => {
      let data: unknown;
      switch (action) {
        case 'trace_aes_key_schedule':
          data = await httpClient.post('/api/crypto_keys/trace_aes', { buffer_address });
          break;
        case 'scan_for_round_keys':
          data = await httpClient.post('/api/crypto_keys/scan_round_keys', { buffer_address });
          break;
        case 'validate_key_expansion':
          data = await httpClient.post('/api/crypto_keys/validate_expansion', { buffer_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
