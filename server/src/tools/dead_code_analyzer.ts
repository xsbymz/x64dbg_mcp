import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDeadCodeAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_dead_code_analyzer',
    'Identify dead, unexecuted, unreachable code blocks, junk instructions, and opaque predicate junk sequences in binary modules.',
    {
      action: z.enum(['analyze', 'find_unreachable', 'strip_deadblocks']).describe('Dead code analysis action'),
      start_address: z.string().optional().describe('Function start address or module base'),
      depth: z.number().optional().default(50),
    },
    async ({ action, start_address, depth }) => {
      let data: unknown;
      switch (action) {
        case 'analyze':
          data = await httpClient.post('/api/deadcode/analyze', { start_address, depth });
          break;
        case 'find_unreachable':
          data = await httpClient.post('/api/deadcode/find_unreachable', { start_address });
          break;
        case 'strip_deadblocks':
          data = await httpClient.post('/api/deadcode/strip_deadblocks', { start_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
