import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerResourceTools(server: McpServer) {
  server.tool(
    'x64dbg_resources',
    'PE resource directory enumeration and extraction. ' +
    'Actions: list (enumerate all PE resources: type, name, id, language, size, address), ' +
    'extract (extract a specific resource by ID and type, returns base64 data).',
    {
      action: z.enum(['list', 'extract']).describe('Resource action'),
      module: z.string().describe('Module name (e.g. "main.exe", "target.dll")'),
      id: z.string().optional().describe('Resource ID (required for extract)'),
      type: z.string().optional().describe('Resource type (required for extract, e.g. "RT_ICON", "RT_MANIFEST")')
    },
    async ({ action, module, id, type }) => {
      try {
        let data: unknown;
        const params: Record<string, string> = { module };

        if (action === 'extract') {
          if (!id || !type) throw new Error('id and type are required for extract action');
          params.id = id;
          params.type = type;
          data = await httpClient.get('/api/resources/extract', params);
        } else {
          data = await httpClient.get('/api/resources/list', params);
        }

        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
