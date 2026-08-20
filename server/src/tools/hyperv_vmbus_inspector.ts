import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHypervVmbusInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_hyperv_vmbus_inspector',
    'Hyper-V VMBus channel endpoints, SynIC Synthetic Interrupt Controller, and Hypercall trampoline inspector.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('enum_channels')
        }),
        z.object({
          action: z.literal('inspect_hypercall_page')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'enum_channels':
            data = await httpClient.post('/api/vmbus/enum_channels', {});
            break;
          case 'inspect_hypercall_page':
            data = await httpClient.post('/api/vmbus/inspect_hypercall_page', {});
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
