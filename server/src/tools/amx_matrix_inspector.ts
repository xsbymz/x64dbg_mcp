import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAmxMatrixInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_amx_matrix_inspector',
    'Intel Advanced Matrix Extensions (AMX) TILECFG palette and 8KB Tile Registers (TMM0-TMM7) inspector.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('tilecfg_status')
        }),
        z.object({
          action: z.literal('dump_tmm_registers')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'tilecfg_status':
            data = await httpClient.post('/api/amx/tilecfg_status', {});
            break;
          case 'dump_tmm_registers':
            data = await httpClient.post('/api/amx/dump_tmm_registers', {});
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
