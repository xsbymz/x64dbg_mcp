import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSehCxxCatchBlockMapperTools(server: McpServer) {
  server.tool(
    'x64dbg_seh_cxx_catch_block_mapper',
    'Map C++ try/catch blocks, ThrowInfo, CatchableTypeArray, and RTTI exception type descriptors from .rdata sections to understand C++ exception structures.',
    {
      action: z.enum(['map_cxx_catch_blocks', 'parse_throw_info', 'inspect_catchable_types']).describe('C++ Exception mapper action'),
      throw_info_address: z.string().optional().describe('Virtual address of _ThrowInfo struct in .rdata'),
    },
    async ({ action, throw_info_address }) => {
      let data: unknown;
      switch (action) {
        case 'map_cxx_catch_blocks':
          data = await httpClient.get('/api/cxx_eh/catch_blocks');
          break;
        case 'parse_throw_info':
          data = await httpClient.post('/api/cxx_eh/throw_info', { throw_info_address });
          break;
        case 'inspect_catchable_types':
          data = await httpClient.post('/api/cxx_eh/catchable_types', { throw_info_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
