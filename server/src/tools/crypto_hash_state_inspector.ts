import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCryptoHashStateInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_crypto_hash_state_inspector',
    'Extract intermediate cryptographic hash working state buffers (SHA-256 H0-H7 states, SHA-512 state arrays, MD5 A/B/C/D contexts) from stack/heap memory.',
    {
      action: z.enum(['scan_hash_states', 'extract_sha256_state', 'extract_sha512_state', 'extract_md5_state']).describe('Hash inspector action'),
      address: z.string().optional().describe('Address of the hash context buffer'),
    },
    async ({ action, address }) => {
      let data: unknown;
      switch (action) {
        case 'scan_hash_states':
          data = await httpClient.get('/api/hash_state/scan');
          break;
        case 'extract_sha256_state':
          data = await httpClient.post('/api/hash_state/sha256', { address });
          break;
        case 'extract_sha512_state':
          data = await httpClient.post('/api/hash_state/sha512', { address });
          break;
        case 'extract_md5_state':
          data = await httpClient.post('/api/hash_state/md5', { address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
