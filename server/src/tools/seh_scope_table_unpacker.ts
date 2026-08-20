import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSehScopeTableUnpackerTools(server: McpServer) {
  server.tool(
    'x64dbg_seh_scope_table_unpacker',
    'Parse MSVC SEH C++ __try/__except/__finally ScopeTables (EH4_SCOPETABLE, EH3_SCOPETABLE) and extract filter expressions and handler blocks.',
    {
      action: z.enum(['parse_scope_table', 'list_function_handlers', 'inspect_eh4_header']).describe('SEH ScopeTable action'),
      function_address: z.string().optional().describe('Virtual address of function containing MSVC SEH handlers'),
    },
    async ({ action, function_address }) => {
      let data: unknown;
      switch (action) {
        case 'parse_scope_table':
          data = await httpClient.post('/api/seh_scopetable/parse', { function_address });
          break;
        case 'list_function_handlers':
          data = await httpClient.post('/api/seh_scopetable/handlers', { function_address });
          break;
        case 'inspect_eh4_header':
          data = await httpClient.post('/api/seh_scopetable/eh4_header', { function_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
