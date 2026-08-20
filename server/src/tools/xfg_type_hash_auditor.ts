import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerXfgTypeHashAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_xfg_type_hash_auditor',
    'Windows 11 Extended Flow Guard (XFG) 64-bit prototype type hash auditor and type-confusion analyzer.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('audit_callsites'),
          start_address: z.string().optional(),
          size: z.number().optional()
        }),
        z.object({
          action: z.literal('find_compatible_targets'),
          type_hash: z.string()
        }),
        z.object({
          action: z.literal('type_confusion_matrix')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'audit_callsites':
            data = await httpClient.post('/api/xfg/audit_callsites', {
              start_address: action.start_address,
              size: action.size
            });
            break;
          case 'find_compatible_targets':
            data = await httpClient.post('/api/xfg/find_compatible_targets', {
              type_hash: action.type_hash
            });
            break;
          case 'type_confusion_matrix':
            data = await httpClient.post('/api/xfg/type_confusion_matrix', {});
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
