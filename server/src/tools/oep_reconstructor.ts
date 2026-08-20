import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerOepReconstructorTools(server: McpServer) {
  server.tool(
    'x64dbg_oep_reconstructor',
    'Original Entry Point (OEP) tail-jump finder, packer boundary detector, and PE entry point reconstructor.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('find_tail_jump')
        }),
        z.object({
          action: z.literal('reconstruct_header')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'find_tail_jump':
            data = await httpClient.post('/api/oep/find_tail_jump', {});
            break;
          case 'reconstruct_header':
            data = await httpClient.post('/api/oep/reconstruct_header', {});
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
