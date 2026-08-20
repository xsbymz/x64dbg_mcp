import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeCoffSymbolTableParserTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_coff_symbol_table_parser',
    'Parse legacy PE COFF Symbol Table (IMAGE_SYMBOL), Auxiliary Symbols, and String Table if present in debug builds or OBJ files.',
    {
      action: z.enum(['parse_coff_symbols', 'get_string_table', 'count_coff_symbols']).describe('COFF symbol action'),
      module_name: z.string().optional().describe('Module name (defaults to primary module)'),
    },
    async ({ action, module_name }) => {
      let data: unknown;
      switch (action) {
        case 'parse_coff_symbols':
          data = await httpClient.post('/api/coff_symbols/parse', { module_name });
          break;
        case 'get_string_table':
          data = await httpClient.post('/api/coff_symbols/strings', { module_name });
          break;
        case 'count_coff_symbols':
          data = await httpClient.post('/api/coff_symbols/count', { module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
