import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeRichHeaderVerifierTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_rich_header_verifier',
    'Verify Microsoft Rich PE Header checksum, validate DanS decryption key against DOS header checksum, and detect header tampering.',
    {
      action: z.enum(['verify_rich_checksum', 'detect_rich_tampering', 'get_dans_xor_key']).describe('Rich verifier action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'verify_rich_checksum':
          data = await httpClient.get('/api/rich_verify/checksum');
          break;
        case 'detect_rich_tampering':
          data = await httpClient.get('/api/rich_verify/tampering');
          break;
        case 'get_dans_xor_key':
          data = await httpClient.get('/api/rich_verify/key');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
