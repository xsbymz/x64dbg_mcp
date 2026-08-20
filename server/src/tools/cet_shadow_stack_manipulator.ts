import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCetShadowStackManipulatorTools(server: McpServer) {
  server.tool(
    'x64dbg_cet_shadow_stack_manipulator',
    'Intel Control-flow Enforcement Technology (CET) hardware shadow stack, RSTORSSP tokens, and Indirect Branch Tracking (IBT) validator.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('read_shadow_stack')
        }),
        z.object({
          action: z.literal('audit_ssp_tokens')
        }),
        z.object({
          action: z.literal('scan_endbr_violations'),
          start_address: z.string().optional(),
          size: z.number().optional()
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'read_shadow_stack':
            data = await httpClient.post('/api/cet/read_shadow_stack', {});
            break;
          case 'audit_ssp_tokens':
            data = await httpClient.post('/api/cet/audit_ssp_tokens', {});
            break;
          case 'scan_endbr_violations':
            data = await httpClient.post('/api/cet/scan_endbr_violations', {
              start_address: action.start_address,
              size: action.size
            });
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
