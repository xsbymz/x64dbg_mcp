import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCryptoStreamCipherDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_crypto_stream_cipher_detector',
    'Identify symmetric stream cipher state structures in memory (RC4 S-box 256-byte permutations, ChaCha20 64-byte state matrix, Salsa20 quarter-round loops).',
    {
      action: z.enum(['scan_rc4_state', 'scan_chacha20_state', 'detect_stream_ciphers']).describe('Stream cipher action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'scan_rc4_state':
          data = await httpClient.get('/api/stream_cipher/rc4');
          break;
        case 'scan_chacha20_state':
          data = await httpClient.get('/api/stream_cipher/chacha20');
          break;
        case 'detect_stream_ciphers':
          data = await httpClient.get('/api/stream_cipher/detect');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
