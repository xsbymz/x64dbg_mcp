import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerV8JitObjectInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_v8_jit_object_inspector',
    'Chrome V8 / SpiderMonkey JSObject hidden classes (Maps/Shapes), pointer compression cages, and WebAssembly JIT memory inspector.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('inspect_js_object'),
          object_address: z.string().optional()
        }),
        z.object({
          action: z.literal('resolve_compressed_pointer'),
          compressed_offset: z.string().optional()
        }),
        z.object({
          action: z.literal('scan_wasm_rwx')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'inspect_js_object':
            data = await httpClient.post('/api/v8/inspect_js_object', {
              object_address: action.object_address
            });
            break;
          case 'resolve_compressed_pointer':
            data = await httpClient.post('/api/v8/resolve_compressed_pointer', {
              compressed_offset: action.compressed_offset
            });
            break;
          case 'scan_wasm_rwx':
            data = await httpClient.post('/api/v8/scan_wasm_rwx', {});
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
