import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAuditTools(server: McpServer) {
  server.tool(
    'x64dbg_audit',
    'View audit log of all MCP requests and security events. ' +
    'Actions: log (view recent audit log entries), stats (get connection and request statistics), clear (clear audit log).',
    {
      action: z.enum(['log', 'stats', 'clear']).describe('Audit action'),
      limit: z.number().optional().default(100).describe('Max entries to return (log action)')
    },
    async ({ action, limit }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'log':
            data = await httpClient.get('/api/audit/log', { limit: String(limit ?? 100) });
            break;
          case 'stats':
            data = await httpClient.get('/api/audit/stats');
            break;
          case 'clear':
            data = await httpClient.post('/api/audit/clear', {});
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
