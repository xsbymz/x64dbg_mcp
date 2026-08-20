import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerTaintTools(server: McpServer) {
  server.tool(
    'x64dbg_taint',
    'Basic taint tracking for exploit development and data-flow analysis. ' +
    'Actions: mark (mark memory range as tainted), clear (clear taint from specific range or all), ' +
    'status (get current taint state), trace_step (perform one taint propagation step after stepping the debugger).',
    {
      action: z.enum(['mark', 'clear', 'status', 'trace_step']).describe('Taint action'),
      address: z.string().optional().describe('Memory address to mark/clear (hex or expression)'),
      size: z.number().optional().default(256).describe('Size in bytes to mark/clear'),
      clear_all: z.boolean().optional().default(false).describe('Clear all taint (clear action only)')
    },
    async ({ action, address, size, clear_all }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'mark':
            if (!address) throw new Error('address is required for mark action');
            data = await httpClient.post('/api/taint/mark', { address, size });
            break;
          case 'clear':
            data = await httpClient.post('/api/taint/clear', {
              address: address || '',
              all: clear_all
            });
            break;
          case 'status':
            data = await httpClient.get('/api/taint/status');
            break;
          case 'trace_step':
            data = await httpClient.post('/api/taint/trace_step', {});
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
