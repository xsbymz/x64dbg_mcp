import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDynamicStubUnfolderTools(server: McpServer) {
  server.tool(
    'x64dbg_dynamic_stub_unfolder',
    'Detect and de-obfuscate single-instruction jumping stubs (push reg; ret, call $+5; pop reg, jmp [rip+offset]) and resolve opaque jump chains.',
    {
      action: z.enum(['unfold_stubs', 'resolve_push_ret_chains', 'trace_opaque_jumps']).describe('Stub unfolder action'),
      start_address: z.string().optional().describe('Virtual address to begin tracing and unfolding stubs from'),
    },
    async ({ action, start_address }) => {
      let data: unknown;
      switch (action) {
        case 'unfold_stubs':
          data = await httpClient.post('/api/stub_unfold/unfold', { start_address });
          break;
        case 'resolve_push_ret_chains':
          data = await httpClient.post('/api/stub_unfold/push_ret', { start_address });
          break;
        case 'trace_opaque_jumps':
          data = await httpClient.post('/api/stub_unfold/opaque_jumps', { start_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
