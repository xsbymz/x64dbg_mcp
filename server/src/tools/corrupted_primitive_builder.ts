import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCorruptedPrimitiveBuilderTools(server: McpServer) {
  server.tool(
    'x64dbg_corrupted_primitive_builder',
    'Corrupted C++ std::vector, BSTR, fake vtable, and arbitrary memory read/write primitive synthesizer.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('vector_oob'),
          vector_address: z.string().optional(),
          target_address: z.string().optional()
        }),
        z.object({
          action: z.literal('fake_vtable'),
          fake_vtable_address: z.string().optional(),
          payload_address: z.string().optional()
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'vector_oob':
            data = await httpClient.post('/api/primitives/vector_oob', {
              vector_address: action.vector_address,
              target_address: action.target_address
            });
            break;
          case 'fake_vtable':
            data = await httpClient.post('/api/primitives/fake_vtable', {
              fake_vtable_address: action.fake_vtable_address,
              payload_address: action.payload_address
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
