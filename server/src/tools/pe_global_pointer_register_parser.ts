import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeGlobalPointerRegisterParserTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_global_pointer_register_parser',
    'Inspect IMAGE_DIRECTORY_ENTRY_GLOBALPTR (RVA of the Global Pointer register table relative data offsets).',
    {
      action: z.enum(['parse_global_pointer', 'get_gp_relative_target', 'check_gp_validity']).describe('Global pointer action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'parse_global_pointer':
          data = await httpClient.get('/api/globalptr/parse');
          break;
        case 'get_gp_relative_target':
          data = await httpClient.get('/api/globalptr/target');
          break;
        case 'check_gp_validity':
          data = await httpClient.get('/api/globalptr/validity');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
