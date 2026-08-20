import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerXsaveAvx512InspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_xsave_avx512_inspector',
    'Extended Processor State (XSAVE/XRSTOR, AVX-512, AMX, PKRU) Inspector. Inspect XCR0 feature masks, dump ZMM0-ZMM31 registers, opmask k0-k7, and memory protection keys.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('get_features')
        }),
        z.object({
          action: z.literal('dump_zmm_registers')
        }),
        z.object({
          action: z.literal('inspect_pkru')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'get_features':
            data = await httpClient.post('/api/xsave/features', {});
            break;
          case 'dump_zmm_registers':
            data = await httpClient.post('/api/xsave/zmm_dump', {});
            break;
          case 'inspect_pkru':
            data = await httpClient.post('/api/xsave/pkru_state', {});
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
