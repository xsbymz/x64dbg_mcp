import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRustPanicUnwinderTools(server: McpServer) {
  server.tool(
    'x64dbg_rust_panic_unwinder',
    'Rust v0 demangler and core::panicking::panic_fmt stack frame and panic hook unwinder.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('demangle_v0'),
          mangled_name: z.string().optional()
        }),
        z.object({
          action: z.literal('trace_panic_frames')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'demangle_v0':
            data = await httpClient.post('/api/rust/demangle_v0', {
              mangled_name: action.mangled_name
            });
            break;
          case 'trace_panic_frames':
            data = await httpClient.post('/api/rust/trace_panic_frames', {});
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
