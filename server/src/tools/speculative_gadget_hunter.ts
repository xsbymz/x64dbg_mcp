import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSpeculativeGadgetHunterTools(server: McpServer) {
  server.tool(
    'x64dbg_speculative_gadget_hunter',
    'Spectre Variant 1 bounds-check bypass, Variant 2 indirect branch target, and speculative execution disclosure gadget hunter.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('scan_v1_bounds_bypass'),
          start_address: z.string().optional(),
          size: z.number().optional()
        }),
        z.object({
          action: z.literal('scan_v2_indirect_branches')
        }),
        z.object({
          action: z.literal('evaluate_cache_leakage')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'scan_v1_bounds_bypass':
            data = await httpClient.post('/api/speculative/scan_v1_bounds_bypass', {
              start_address: action.start_address,
              size: action.size
            });
            break;
          case 'scan_v2_indirect_branches':
            data = await httpClient.post('/api/speculative/scan_v2_indirect_branches', {});
            break;
          case 'evaluate_cache_leakage':
            data = await httpClient.post('/api/speculative/evaluate_cache_leakage', {});
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
