import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRichHeaderAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_rich_header_analyzer',
    'Parse and decrypt the Microsoft PE Rich Header: extract CompIDs, compiler/linker build versions (MSVC, MASM, UTC), product IDs, and compute Rich Header checksum / DanS hash.',
    {
      action: z.enum(['parse_rich_header', 'compute_rich_hash', 'verify_checksum']).describe('Rich header action'),
      module: z.string().optional().describe('Target module name (defaults to main binary)'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'parse_rich_header':
          data = await httpClient.post('/api/pe/rich/parse', { module });
          break;
        case 'compute_rich_hash':
          data = await httpClient.post('/api/pe/rich/hash', { module });
          break;
        case 'verify_checksum':
          data = await httpClient.post('/api/pe/rich/verify', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
