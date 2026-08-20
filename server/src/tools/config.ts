import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerConfigTools(server: McpServer) {
  server.tool(
    'x64dbg_config',
    'Generic malware configuration extractor and paginated string scanner. ' +
    'Actions: extract (scan memory for structured config blobs: base64, XORed strings with known prefixes, JSON length-prefixed objects, PE headers at unusual addresses), ' +
    'strings (paginated string scan in a module with encoding selection).',
    {
      action: z.enum(['extract', 'strings']).describe('Config action'),
      module: z.string().optional().describe('Module name (optional for extract; required for strings)'),
      encoding: z.enum(['utf8', 'ascii', 'unicode']).optional().default('utf8').describe('String encoding (strings action)'),
      limit: z.number().optional().default(200).describe('Max strings to return (strings action)'),
      offset: z.number().optional().default(0).describe('Skip first N strings (strings action)'),
      min_size: z.number().optional().default(16).describe('Min blob size in bytes (extract action)'),
      max_scan_size: z.number().optional().default(10485760).describe('Max scan size in bytes (extract action)')
    },
    async ({ action, module, encoding, limit, offset, min_size, max_scan_size }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'extract':
            data = await httpClient.post('/api/config/extract', {
              module: module || '',
              min_size,
              max_scan_size
            });
            break;
          case 'strings':
            if (!module) throw new Error('module is required for strings action');
            data = await httpClient.get('/api/config/strings', {
              module,
              encoding,
              limit: String(limit ?? 200),
              offset: String(offset ?? 0)
            });
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
