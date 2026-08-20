import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDotnetHelperTools(server: McpServer) {
  server.tool(
    'x64dbg_dotnet_helper',
    'Inspect .NET / CLR execution environments: detect CLR runtime versions (clr.dll/coreclr.dll), inspect AppDomains, resolve managed JIT method stubs, and parse CLI metadata headers.',
    {
      action: z.enum(['detect_clr', 'list_appdomains', 'resolve_jit_method', 'parse_cli_header']).describe('.NET analysis action'),
      address: z.string().optional().describe('Address of managed method or JIT stub to inspect'),
      module: z.string().optional().describe('Target module name'),
    },
    async ({ action, address, module }) => {
      let data: unknown;
      switch (action) {
        case 'detect_clr':
          data = await httpClient.get('/api/dotnet/detect_clr');
          break;
        case 'list_appdomains':
          data = await httpClient.get('/api/dotnet/list_appdomains');
          break;
        case 'resolve_jit_method':
          data = await httpClient.post('/api/dotnet/resolve_jit_method', { address });
          break;
        case 'parse_cli_header':
          data = await httpClient.post('/api/dotnet/parse_cli_header', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
