import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeDelayLoadDirectoryParserTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_delay_load_directory_parser',
    'Inspect PE Delay-Load Import Descriptors (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT), helper thunks (__delayLoadHelper2), and delay IATs.',
    {
      action: z.enum(['parse_delay_imports', 'list_delay_modules', 'check_bound_delay_iats']).describe('Delay load action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'parse_delay_imports':
          data = await httpClient.get('/api/delay_load/parse');
          break;
        case 'list_delay_modules':
          data = await httpClient.get('/api/delay_load/modules');
          break;
        case 'check_bound_delay_iats':
          data = await httpClient.get('/api/delay_load/bound_iats');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
