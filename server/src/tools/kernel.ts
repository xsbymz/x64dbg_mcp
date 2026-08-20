import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerKernelTools(server: McpServer) {
  server.tool(
    'x64dbg_kernel',
    'Kernel-mode exploitation helpers: token steal check, pool overflow detection, and kernel callback enumeration.',
    {
      action: z.enum(['token_steal_check', 'pool_overflow_detection', 'callbacks']).describe('Kernel analysis action')
    },
    async ({ action }) => {
      try {
        const data = await httpClient.get(`/api/kernel/${action}`);
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
