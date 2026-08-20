import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerComTypeLibraryParserTools(server: McpServer) {
  server.tool(
    'x64dbg_com_type_library_parser',
    'Extract and parse COM Type Libraries (ITypeLib/ITypeInfo / TYPELIB resource), enumerate coclasses, interfaces, dispatch IDs, and generate IDL/C++ headers.',
    {
      action: z.enum(['parse_typelib', 'list_interfaces', 'export_idl']).describe('TypeLib action'),
      module: z.string().optional().describe('Target module name'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'parse_typelib':
          data = await httpClient.post('/api/typelib/parse', { module });
          break;
        case 'list_interfaces':
          data = await httpClient.post('/api/typelib/interfaces', { module });
          break;
        case 'export_idl':
          data = await httpClient.post('/api/typelib/export_idl', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
