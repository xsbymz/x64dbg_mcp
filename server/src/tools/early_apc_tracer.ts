import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerEarlyApcTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_early_apc_tracer',
    'Early Bird APC injection detector, alertable thread scanner, and Special User APC queue auditor.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('scan_alertable_threads')
        }),
        z.object({
          action: z.literal('audit_queued_routines')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'scan_alertable_threads':
            data = await httpClient.post('/api/apc/scan_alertable_threads', {});
            break;
          case 'audit_queued_routines':
            data = await httpClient.post('/api/apc/audit_queued_routines', {});
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
