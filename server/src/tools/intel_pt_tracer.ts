import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerIntelPtTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_intel_pt_tracer',
    'Intel Processor Trace (Intel PT) hardware execution stream decoder and AFL++ coverage bitmap exporter.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('status')
        }),
        z.object({
          action: z.literal('decode_trace')
        }),
        z.object({
          action: z.literal('export_coverage_bitmap')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'status':
            data = await httpClient.post('/api/intel_pt/status', {});
            break;
          case 'decode_trace':
            data = await httpClient.post('/api/intel_pt/decode_trace', {});
            break;
          case 'export_coverage_bitmap':
            data = await httpClient.post('/api/intel_pt/export_coverage_bitmap', {});
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
