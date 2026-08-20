import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerKernelHandleTableParserTools(server: McpServer) {
  server.tool(
    'x64dbg_kernel_handle_table_parser',
    'Windows kernel multi-level _HANDLE_TABLE structure parser and _HANDLE_TABLE_ENTRY access mask resolver.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('parse_table')
        }),
        z.object({
          action: z.literal('lookup_entry'),
          handle_value: z.number().optional()
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'parse_table':
            data = await httpClient.post('/api/kernel_handles/parse_table', {});
            break;
          case 'lookup_entry':
            data = await httpClient.post('/api/kernel_handles/lookup_entry', {
              handle_value: action.handle_value
            });
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
