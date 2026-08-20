import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAlpcNdrFuzzerTools(server: McpServer) {
  server.tool(
    'x64dbg_alpc_ndr_fuzzer',
    'ALPC & RPC Network Data Representation (NDR) interface deconstructor, MIDL dispatch table analyzer, and type-aware boundary payload mutator.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('parse_ndr_stream')
        }),
        z.object({
          action: z.literal('mutate_payload')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'parse_ndr_stream':
            data = await httpClient.post('/api/alpc_fuzzer/parse_ndr_stream', {});
            break;
          case 'mutate_payload':
            data = await httpClient.post('/api/alpc_fuzzer/mutate_payload', {});
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
