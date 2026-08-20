import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCertAuthenticodeTools(server: McpServer) {
  server.tool(
    'x64dbg_cert_authenticode',
    'Verify Windows Authenticode digital signatures, parse embedded PKCS#7 certificate chains, inspect catalog signatures, and check revocation / timestamp countersignatures.',
    {
      action: z.enum(['verify_module', 'dump_certificates', 'check_revocation', 'inspect_timestamp']).describe('Authenticode verification action'),
      module: z.string().optional().describe('Target module name (defaults to main module)'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'verify_module':
          data = await httpClient.post('/api/cert/verify', { module });
          break;
        case 'dump_certificates':
          data = await httpClient.post('/api/cert/dump', { module });
          break;
        case 'check_revocation':
          data = await httpClient.post('/api/cert/revocation', { module });
          break;
        case 'inspect_timestamp':
          data = await httpClient.post('/api/cert/timestamp', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
