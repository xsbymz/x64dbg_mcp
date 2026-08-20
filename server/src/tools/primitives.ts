import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPrimitiveTools(server: McpServer) {
  server.tool(
    'x64dbg_primitives',
    'Exploit primitive detection: scan for dangerous functions and trace register values at call. ' +
    'Actions: detect (scan loaded modules for arbitrary read/write/info-leak candidates and dangerous functions), ' +
    'trace (set up conditional trace on a function to capture register values and parameters at each call).',
    {
      action: z.enum(['detect', 'trace']).describe('Primitive action'),
      function_address: z.string().optional().describe('Address or symbol of function to trace (required for trace)'),
      max_traces: z.number().optional().default(10).describe('Max trace records to capture (trace action only)')
    },
    async ({ action, function_address, max_traces }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'detect':
            data = await httpClient.get('/api/primitive/detect');
            break;
          case 'trace':
            if (!function_address) throw new Error('function_address is required for trace action');
            data = await httpClient.post('/api/primitive/trace', {
              function_address,
              max_traces
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
