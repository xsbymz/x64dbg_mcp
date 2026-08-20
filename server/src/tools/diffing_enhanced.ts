import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDiffingEnhancedTools(server: McpServer) {
  server.tool(
    'x64dbg_diffing_enhanced',
    'Enhanced binary diffing: semantic diff between modules and comprehensive patch analysis with exploitability assessment.',
    {
      action: z.enum(['semantic', 'patch_analysis']).describe('Diffing action'),
      module1: z.string().optional().describe('First module name (semantic action)'),
      module2: z.string().optional().describe('Second module name (semantic action)')
    },
    async ({ action, module1, module2 }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'semantic':
            if (!module1 || !module2) throw new Error('module1 and module2 are required for semantic action');
            data = await httpClient.post('/api/diff/semantic', { module1, module2 });
            break;
          case 'patch_analysis':
            data = await httpClient.get('/api/diff/patch_analysis');
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
