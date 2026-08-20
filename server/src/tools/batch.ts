import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerBatchTools(server: McpServer) {
  server.tool(
    'x64dbg_batch',
    'Execute multiple independent requests in one HTTP round-trip to reduce latency. ' +
    'Useful for fetching registers, stack, disasm, and modules in parallel. ' +
    'Body: array of {method: "GET"|"POST", path: "/api/...", query?: {...}, body?: {...}}. ' +
    'Max 20 requests per batch. Requests execute sequentially to maintain debugger state consistency.',
    {
      requests: z.array(z.object({
        method: z.enum(['GET', 'POST']),
        path: z.string(),
        query: z.record(z.string()).optional(),
        body: z.any().optional()
      })).max(20).describe('Array of requests to execute (max 20)')
    },
    async ({ requests }) => {
      try {
        const data = await httpClient.post('/api/batch', { requests });
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
