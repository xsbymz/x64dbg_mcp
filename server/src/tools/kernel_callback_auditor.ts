import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerKernelCallbackAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_kernel_callback_auditor',
    'Kernel process/thread creation callbacks, ObRegisterCallbacks object filters, and FltMgr minifilter security inspector.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('process_thread')
        }),
        z.object({
          action: z.literal('object_filters')
        }),
        z.object({
          action: z.literal('minifilters')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'process_thread':
            data = await httpClient.post('/api/kernel_callbacks/process_thread', {});
            break;
          case 'object_filters':
            data = await httpClient.post('/api/kernel_callbacks/object_filters', {});
            break;
          case 'minifilters':
            data = await httpClient.post('/api/kernel_callbacks/minifilters', {});
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
