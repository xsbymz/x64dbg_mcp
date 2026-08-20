import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCryptoTools(server: McpServer) {
  server.tool(
    'x64dbg_crypto',
    'FindCrypt automated cryptographic signature scanner. Identifies AES S-boxes/InvS-boxes, MD5, SHA-1, SHA-256, SHA-512, ChaCha20/Salsa20, CRC32, TEA delta, and Base64 tables across process memory or specific modules.',
    {
      action: z.enum(['scan']).describe('Crypto scan action'),
      module: z.string().optional().describe('Restrict scan to a specific module name (e.g. "target.exe"), or omit for full memory scan')
    },
    async ({ action, module }) => {
      try {
        const body: Record<string, unknown> = {};
        if (module) body.module = module;
        const data = await httpClient.post('/api/crypto/scan', body);
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
