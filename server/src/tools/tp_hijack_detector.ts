import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerTpHijackDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_thread_pool_hijack_detector',
    'Thread Pool Hijacking & Worker Factory Exploit Auditor. Detect unbacked callbacks, hijacked TP_WORK/TP_TIMER structures, and worker factory manipulation.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('scan_thread_pool')
        }),
        z.object({
          action: z.literal('audit_callbacks')
        }),
        z.object({
          action: z.literal('inspect_worker_factory')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'scan_thread_pool':
            data = await httpClient.post('/api/tp_hijack/scan', {});
            break;
          case 'audit_callbacks':
            data = await httpClient.post('/api/tp_hijack/callbacks', {});
            break;
          case 'inspect_worker_factory':
            data = await httpClient.post('/api/tp_hijack/factory_info', {});
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
