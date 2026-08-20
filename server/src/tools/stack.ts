import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerStackTools(server: McpServer) {
  server.tool(
    'x64dbg_stack',
    'Stack operations: call stack unwinding, raw memory read, smart function arguments & parameter resolver, pointers, SEH chain, return address. ' +
    'Actions: arguments (smart caller parameter resolver based on x64 Microsoft FastCall / x86 cdecl, with automatic string and pointer previews), ' +
    'get_call_stack (unwind stack frames), read (read raw stack memory), pointers (find pointer-like values on stack), ' +
    'seh_chain (SEH handlers on stack), return_address (inspect return address at top of stack), comment (comment on stack address).',
    {
      action: z.discriminatedUnion("action", [
        z.object({
          action: z.literal("arguments"),
          count: z.number().optional().default(8).describe("Number of function arguments to resolve (default 8)")
        }),
        z.object({
          action: z.literal("get_call_stack"),
          handle: z.string().optional().describe("Thread handle (hex)"),
          max_depth: z.string().optional().default("50")
        }),
        z.object({
          action: z.literal("read"),
          address: z.string().optional().default("csp"),
          size: z.string().optional().default("256")
        }),
        z.object({ action: z.literal("pointers") }),
        z.object({ action: z.literal("seh_chain") }),
        z.object({ action: z.literal("return_address") }),
        z.object({ action: z.literal("comment"), address: z.string() })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'arguments':
            data = await httpClient.get('/api/stack/arguments', { count: String(action.count) });
            break;
          case 'get_call_stack':
            if (action.handle) {
              data = await httpClient.get('/api/stack/callstack_thread', { handle: action.handle });
            } else {
              data = await httpClient.get('/api/stack/trace', { max_depth: action.max_depth });
            }
            break;
          case 'read':
            data = await httpClient.get('/api/stack/read', { address: action.address, size: action.size });
            break;
          case 'pointers':
            data = await httpClient.get('/api/stack/pointers');
            break;
          case 'seh_chain':
            data = await httpClient.get('/api/stack/seh_chain');
            break;
          case 'return_address':
            data = await httpClient.get('/api/stack/return_address');
            break;
          case 'comment':
            data = await httpClient.get('/api/stack/comment', { address: action.address });
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
