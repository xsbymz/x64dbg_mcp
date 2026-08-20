import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerLbrBranchRingInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_lbr_branch_ring_inspector',
    'Hardware Last Branch Record (LBR) & Branch Trace Store (BTS) circular history ring buffer inspector and ROP anomaly detector.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('status')
        }),
        z.object({
          action: z.literal('read_branch_records')
        }),
        z.object({
          action: z.literal('detect_rop_anomalies')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'status':
            data = await httpClient.post('/api/lbr/status', {});
            break;
          case 'read_branch_records':
            data = await httpClient.post('/api/lbr/read_branch_records', {});
            break;
          case 'detect_rop_anomalies':
            data = await httpClient.post('/api/lbr/detect_rop_anomalies', {});
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
