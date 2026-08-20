import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCryptoHunterTools(server: McpServer) {
  server.tool(
    'x64dbg_crypto_hunter',
    'Scan debuggee memory and modules for cryptographic constants, lookup tables (AES S-box, ChaCha20, SHA-256 IVs, MD5, CRC32), and RSA/ECC key schedules.',
    {
      action: z.enum(['scan_tables', 'find_keys', 'identify_primitive']).describe('Crypto scan operation'),
      module: z.string().optional().describe('Target module name (empty for entire process memory)'),
      algorithm: z.enum(['all', 'aes', 'chacha20', 'sha256', 'md5', 'rsa', 'crc32']).optional().default('all'),
    },
    async ({ action, module, algorithm }) => {
      let data: unknown;
      switch (action) {
        case 'scan_tables':
          data = await httpClient.post('/api/crypto/scan_tables', { module, algorithm });
          break;
        case 'find_keys':
          data = await httpClient.post('/api/crypto/find_keys', { module, algorithm });
          break;
        case 'identify_primitive':
          data = await httpClient.post('/api/crypto/identify_primitive', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
