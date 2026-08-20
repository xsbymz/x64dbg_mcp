import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSecurityTools(server: McpServer) {
  server.tool(
    'x64dbg_security',
    'Security status and hardening verification. ' +
    'Actions: status (check auth, rate limiting, and connection status), verify_token (verify current token is valid), ' +
    'hardening_report (full security posture report).',
    {
      action: z.enum(['status', 'verify_token', 'hardening_report']).describe('Security action')
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'status':
            data = await httpClient.get('/api/security/status');
            break;
          case 'verify_token':
            data = await httpClient.get('/api/security/verify_token');
            break;
          case 'hardening_report':
            data = await httpClient.get('/api/security/hardening_report');
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
