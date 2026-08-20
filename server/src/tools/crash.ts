import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCrashTools(server: McpServer) {
  server.tool(
    'x64dbg_crash',
    'Crash triage, exception code reference, and last exception inspection. ' +
    'Actions: triage (full crash root-cause analysis: exception code, faulting instruction, register snapshot, stack dump, SEH chain, memory page info, heuristic classification), ' +
    'buckets (list known Windows exception codes with descriptions), ' +
    'last (get last exception info: code, address, flags).',
    {
      action: z.discriminatedUnion('action', [
        z.object({ action: z.literal('triage') }),
        z.object({ action: z.literal('buckets') }),
        z.object({ action: z.literal('last') })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'triage':
            data = await httpClient.get('/api/crash/triage');
            break;
          case 'buckets':
            data = await httpClient.get('/api/crash/buckets');
            break;
          case 'last':
            data = await httpClient.get('/api/crash/last');
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
