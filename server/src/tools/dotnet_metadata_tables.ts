import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDotnetMetadataTablesTools(server: McpServer) {
  server.tool(
    'x64dbg_dotnet_metadata_tables',
    'Parse .NET CLI metadata streams (#~, #Strings, #US, #GUID, #Blob) and table rows (TypeDef, MethodDef, Param, MemberRef, Field, ModuleRef).',
    {
      action: z.enum(['parse_streams', 'dump_typedef_table', 'dump_methoddef_table', 'resolve_token']).describe('CLR metadata action'),
      module: z.string().optional().describe('Target module name'),
      token: z.string().optional().describe('Metadata token hex (e.g. 0x06000001)'),
    },
    async ({ action, module, token }) => {
      let data: unknown;
      switch (action) {
        case 'parse_streams':
          data = await httpClient.post('/api/clr_meta/streams', { module });
          break;
        case 'dump_typedef_table':
          data = await httpClient.post('/api/clr_meta/typedefs', { module });
          break;
        case 'dump_methoddef_table':
          data = await httpClient.post('/api/clr_meta/methoddefs', { module });
          break;
        case 'resolve_token':
          data = await httpClient.post('/api/clr_meta/resolve_token', { module, token });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
