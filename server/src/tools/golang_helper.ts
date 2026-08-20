import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerGolangHelperTools(server: McpServer) {
  server.tool(
    'x64dbg_golang_helper',
    'Parse Go runtime structures (pclntab / moduledata), recover stripped function names, inspect Goroutine stack frames, and extract Go type descriptors.',
    {
      action: z.enum(['parse_pclntab', 'list_goroutines', 'extract_types', 'recover_func_names']).describe('Go analysis action'),
      module: z.string().optional().describe('Target module name (defaults to main module)'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'parse_pclntab':
          data = await httpClient.post('/api/golang/parse_pclntab', { module });
          break;
        case 'list_goroutines':
          data = await httpClient.get('/api/golang/list_goroutines');
          break;
        case 'extract_types':
          data = await httpClient.post('/api/golang/extract_types', { module });
          break;
        case 'recover_func_names':
          data = await httpClient.post('/api/golang/recover_func_names', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
