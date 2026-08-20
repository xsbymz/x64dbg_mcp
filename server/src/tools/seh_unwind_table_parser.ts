import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSehUnwindTableParserTools(server: McpServer) {
  server.tool(
    'x64dbg_seh_unwind_table_parser',
    'Parse x64 PE .pdata and .xdata sections, extract RUNTIME_FUNCTION table entries, decode UNWIND_INFO opcodes (UWOP_PUSH_NONVOL, UWOP_ALLOC_LARGE), and inspect chained unwind info.',
    {
      action: z.enum(['parse_pdata', 'get_function_unwind_info', 'validate_runtime_functions']).describe('SEH unwind table action'),
      module: z.string().optional().describe('Target module name'),
      address: z.string().optional().describe('Function address to look up unwind info'),
    },
    async ({ action, module, address }) => {
      let data: unknown;
      switch (action) {
        case 'parse_pdata':
          data = await httpClient.post('/api/seh_unwind/parse_pdata', { module });
          break;
        case 'get_function_unwind_info':
          data = await httpClient.post('/api/seh_unwind/function_info', { module, address });
          break;
        case 'validate_runtime_functions':
          data = await httpClient.post('/api/seh_unwind/validate', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
