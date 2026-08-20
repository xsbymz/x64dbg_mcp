import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerTlsCallbackAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_tls_callback_analyzer',
    'Inspect PE TLS Directory, enumerate all TLS Callbacks, set automatic breakpoints on TLS callbacks before entry point, and analyze TLS slot indices.',
    {
      action: z.enum(['list_tls_callbacks', 'set_tls_breakpoints', 'inspect_tls_directory']).describe('TLS callback action'),
      module: z.string().optional().describe('Target module name'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'list_tls_callbacks':
          data = await httpClient.post('/api/tls/callbacks', { module });
          break;
        case 'set_tls_breakpoints':
          data = await httpClient.post('/api/tls/set_breakpoints', { module });
          break;
        case 'inspect_tls_directory':
          data = await httpClient.post('/api/tls/directory', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
