import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCorruptionTools(server: McpServer) {
  server.tool(
    'x64dbg_corruption',
    'Memory corruption vulnerability detection: stack canary analysis, format string detection, heap overflow checks, and use-after-free candidate identification.',
    {
      action: z.enum(['stack_canary', 'format_string', 'heap_overflow', 'uaf_candidates']).describe('Corruption detection type'),
      address: z.string().optional().describe('Memory address to analyze'),
      heap_address: z.string().optional().describe('Heap base address (heap_overflow action)'),
      module: z.string().optional().describe('Module name (uaf_candidates action)'),
      count: z.number().optional().default(64).describe('Instructions to scan (format_string action)')
    },
    async ({ action, address, heap_address, module, count }) => {
      try {
        let data: unknown;
        const params: Record<string, string> = {};
        if (address) params.address = address;
        if (heap_address) params.heap_address = heap_address;
        if (module) params.module = module;
        if (count !== undefined) params.count = String(count);

        switch (action) {
          case 'stack_canary':
            data = await httpClient.get('/api/corruption/stack_canary', params);
            break;
          case 'format_string':
            data = await httpClient.get('/api/corruption/format_string', params);
            break;
          case 'heap_overflow':
            data = await httpClient.get('/api/corruption/heap_overflow', params);
            break;
          case 'uaf_candidates':
            data = await httpClient.get('/api/corruption/uaf_candidates', params);
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
