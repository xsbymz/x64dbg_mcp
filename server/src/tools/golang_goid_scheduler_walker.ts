import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerGolangGoidSchedulerWalkerTools(server: McpServer) {
  server.tool(
    'x64dbg_golang_goid_scheduler_walker',
    'Go runtime goroutine scheduler (allg, allp, allm) and hchan channel buffer and wait-queue inspector.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('enum_goroutines')
        }),
        z.object({
          action: z.literal('inspect_channel'),
          channel_address: z.string().optional()
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'enum_goroutines':
            data = await httpClient.post('/api/golang/enum_goroutines', {});
            break;
          case 'inspect_channel':
            data = await httpClient.post('/api/golang/inspect_channel', {
              channel_address: action.channel_address
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
