import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSehChainedUnwindHandlerTools(server: McpServer) {
  server.tool(
    'x64dbg_seh_chained_unwind_handler',
    'Unwind and inspect chained RUNTIME_FUNCTION entries (UNWIND_CHAIN_INFO, UNW_FLAG_CHAININFO) spanning non-contiguous code blocks.',
    {
      action: z.enum(['parse_chained_unwind', 'get_parent_runtime_function', 'validate_chain_integrity']).describe('Chained unwind action'),
      address: z.string().describe('Address of the function or chained unwind record'),
    },
    async ({ action, address }) => {
      let data: unknown;
      switch (action) {
        case 'parse_chained_unwind':
          data = await httpClient.post('/api/seh_chain/parse', { address });
          break;
        case 'get_parent_runtime_function':
          data = await httpClient.post('/api/seh_chain/parent', { address });
          break;
        case 'validate_chain_integrity':
          data = await httpClient.post('/api/seh_chain/validate', { address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
