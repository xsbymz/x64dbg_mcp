import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerStringTableIdLookupTools(server: McpServer) {
  server.tool(
    'x64dbg_string_table_id_lookup',
    'Lookup localized resource string table entries (RT_STRING) by exact numeric Resource ID and language ID.',
    {
      action: z.enum(['lookup_by_id', 'lookup_range', 'list_all_string_blocks']).describe('String table lookup action'),
      string_id: z.number().optional().describe('Numeric Resource ID of the string'),
      start_id: z.number().optional().describe('Start of string ID range'),
      end_id: z.number().optional().describe('End of string ID range'),
      module_name: z.string().optional().describe('Module name (defaults to primary module)'),
    },
    async ({ action, string_id, start_id, end_id, module_name }) => {
      let data: unknown;
      switch (action) {
        case 'lookup_by_id':
          data = await httpClient.post('/api/str_table_id/get', { string_id, module_name });
          break;
        case 'lookup_range':
          data = await httpClient.post('/api/str_table_id/range', { start_id, end_id, module_name });
          break;
        case 'list_all_string_blocks':
          data = await httpClient.post('/api/str_table_id/blocks', { module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
