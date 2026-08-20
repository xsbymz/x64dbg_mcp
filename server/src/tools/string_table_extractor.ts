import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerStringTableExtractorTools(server: McpServer) {
  server.tool(
    'x64dbg_string_table_extractor',
    'Extract and dump all localized resource String Tables (RT_STRING) and Message Tables (RT_MESSAGETABLE) embedded in PE binaries.',
    {
      action: z.enum(['extract_string_tables', 'extract_message_tables']).describe('String table action'),
      module: z.string().optional().describe('Target module name'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'extract_string_tables':
          data = await httpClient.post('/api/string_table/extract', { module });
          break;
        case 'extract_message_tables':
          data = await httpClient.post('/api/string_table/message_tables', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
