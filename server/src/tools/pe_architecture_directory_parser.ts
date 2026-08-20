import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeArchitectureDirectoryParserTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_architecture_directory_parser',
    'Parse IMAGE_DIRECTORY_ENTRY_ARCHITECTURE structures and inspect architecture-specific metadata headers (Alpha, IA64, ARM64).',
    {
      action: z.enum(['parse_architecture_directory', 'check_machine_compatibility', 'inspect_architecture_flags']).describe('Architecture dir action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'parse_architecture_directory':
          data = await httpClient.get('/api/arch_dir/parse');
          break;
        case 'check_machine_compatibility':
          data = await httpClient.get('/api/arch_dir/compatibility');
          break;
        case 'inspect_architecture_flags':
          data = await httpClient.get('/api/arch_dir/flags');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
