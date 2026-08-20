import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryPatternReplacerTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_pattern_replacer',
    'Atomic pattern search and replace across virtual memory pages or modules with wildcard bytes (e.g. "48 89 ?? 55" -> "90 90 90 90").',
    {
      action: z.enum(['search_pattern', 'replace_pattern_all', 'replace_pattern_once']).describe('Pattern replacer action'),
      pattern: z.string().describe('Search pattern with hex bytes and optional ?? wildcards'),
      replacement: z.string().optional().describe('Replacement hex bytes'),
      module: z.string().optional().describe('Limit replacement to specific module'),
    },
    async ({ action, pattern, replacement, module }) => {
      let data: unknown;
      switch (action) {
        case 'search_pattern':
          data = await httpClient.post('/api/pattern_replace/search', { pattern, module });
          break;
        case 'replace_pattern_all':
          data = await httpClient.post('/api/pattern_replace/replace_all', { pattern, replacement, module });
          break;
        case 'replace_pattern_once':
          data = await httpClient.post('/api/pattern_replace/replace_once', { pattern, replacement, module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
