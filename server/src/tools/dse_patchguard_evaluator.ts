import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDsePatchguardEvaluatorTools(server: McpServer) {
  server.tool(
    'x64dbg_dse_patchguard_evaluator',
    'Driver Signature Enforcement (DSE / ci!g_CiOptions), test-signing, and PatchGuard kernel debugger state evaluator.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('check_ci_options')
        }),
        z.object({
          action: z.literal('inspect_kd_pitch')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'check_ci_options':
            data = await httpClient.post('/api/dse/check_ci_options', {});
            break;
          case 'inspect_kd_pitch':
            data = await httpClient.post('/api/dse/inspect_kd_pitch', {});
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
