import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeSecurityDirectoryTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_security_directory',
    'Parse the PE Security Directory (WIN_CERTIFICATE / IMAGE_DIRECTORY_ENTRY_SECURITY), extract PKCS#7 signed data, digest algorithms, and timestamp tokens.',
    {
      action: z.enum(['parse_security_directory', 'extract_raw_certificate', 'verify_hash']).describe('PE security directory action'),
      module: z.string().optional().describe('Target module name'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'parse_security_directory':
          data = await httpClient.post('/api/pe_security/parse', { module });
          break;
        case 'extract_raw_certificate':
          data = await httpClient.post('/api/pe_security/extract', { module });
          break;
        case 'verify_hash':
          data = await httpClient.post('/api/pe_security/verify_hash', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
