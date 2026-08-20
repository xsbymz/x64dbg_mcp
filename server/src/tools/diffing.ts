import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDiffingTools(server: McpServer) {
  server.tool(
    'x64dbg_diffing',
    'Binary diffing: compare in-memory modules against on-disk PE, compare two files, and find security patches.',
    {
      action: z.enum(['memory_vs_disk', 'binary', 'find_security_patches']).describe('Diffing action'),
      module: z.string().optional().describe('Module name (required for memory_vs_disk)'),
      file_a: z.string().optional().describe('First file path (required for binary)'),
      file_b: z.string().optional().describe('Second file path (required for binary)')
    },
    async ({ action, module, file_a, file_b }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'memory_vs_disk':
            if (!module) throw new Error('module is required for memory_vs_disk action');
            data = await httpClient.post('/api/diff/memory_vs_disk', { module });
            break;
          case 'binary':
            if (!file_a || !file_b) throw new Error('file_a and file_b are required for binary action');
            data = await httpClient.post('/api/diff/binary', { file_a, file_b });
            break;
          case 'find_security_patches':
            if (!module) throw new Error('module is required for find_security_patches action');
            data = await httpClient.post('/api/diff/find_security_patches', { module });
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
