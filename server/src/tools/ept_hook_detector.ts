import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerEptHookDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_ept_hook_detector',
    'Hypervisor EPT (Extended Page Tables) and Split-TLB stealth hook detector and read-vs-execute cycle latency analyzer.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('scan_split_tlb'),
          start_address: z.string().optional(),
          size: z.number().optional()
        }),
        z.object({
          action: z.literal('timing_differential')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'scan_split_tlb':
            data = await httpClient.post('/api/ept/scan_split_tlb', {
              start_address: action.start_address,
              size: action.size
            });
            break;
          case 'timing_differential':
            data = await httpClient.post('/api/ept/timing_differential', {});
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
