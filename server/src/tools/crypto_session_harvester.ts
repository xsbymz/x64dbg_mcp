import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCryptoSessionHarvesterTools(server: McpServer) {
  server.tool(
    'x64dbg_crypto_session_harvester',
    'Cryptographic constant scanner (AES S-Boxes, ChaCha20 constants) and live session key/IV memory harvester.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('scan_sbox_constants')
        }),
        z.object({
          action: z.literal('intercept_session_keys')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'scan_sbox_constants':
            data = await httpClient.post('/api/crypto_harvest/scan_sbox_constants', {});
            break;
          case 'intercept_session_keys':
            data = await httpClient.post('/api/crypto_harvest/intercept_session_keys', {});
            break;
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
