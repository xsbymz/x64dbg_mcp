import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSymbolicMbaRewriterTools(server: McpServer) {
  server.tool(
    'x64dbg_symbolic_mba_rewriter',
    'Apply SMT/Z3 term rewrite rules to simplify high-degree Mixed Boolean-Arithmetic (MBA) expressions into canonical linear arithmetic forms.',
    {
      action: z.enum(['rewrite_expression', 'verify_equivalence', 'list_known_mba_identities']).describe('MBA rewriter action'),
      expression: z.string().optional().describe('Obfuscated arithmetic expression (e.g. (x ^ y) + 2 * (x & y))'),
    },
    async ({ action, expression }) => {
      let data: unknown;
      switch (action) {
        case 'rewrite_expression':
          data = await httpClient.post('/api/mba_rewrite/simplify', { expression });
          break;
        case 'verify_equivalence':
          data = await httpClient.post('/api/mba_rewrite/verify', { expression });
          break;
        case 'list_known_mba_identities':
          data = await httpClient.get('/api/mba_rewrite/identities');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
