import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerExceptionTools(server: McpServer) {
  server.tool(
    'x64dbg_exceptions',
    'Manage exception breakpoints, inspect the Structured Exception Handling (SEH) chain, list Windows exception codes, or skip exceptions. ' +
    'Actions: set (set first/second chance exception breakpoint), delete, list (active exception BPs), list_codes (known Windows NTSTATUS exception codes), skip (ignore exception and continue), seh_chain (read current SEH handler chain).',
    {
      action: z.discriminatedUnion("action", [
        z.object({
          action: z.literal("set"),
          code: z.string().describe("Exception code in hex (e.g. 'C0000005' for Access Violation, '80000003' for Breakpoint)"),
          chance: z.enum(['first', 'second', 'all']).optional().default("first")
        }),
        z.object({ action: z.literal("delete"), code: z.string() }),
        z.object({ action: z.literal("list") }),
        z.object({ action: z.literal("list_codes") }),
        z.object({ action: z.literal("skip") }),
        z.object({ action: z.literal("seh_chain") })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'set':
            data = await httpClient.post('/api/exceptions/set_bp', { code: action.code, chance: action.chance });
            break;
          case 'delete':
            data = await httpClient.post('/api/exceptions/delete_bp', { code: action.code });
            break;
          case 'list':
            data = await httpClient.get('/api/exceptions/list_bps');
            break;
          case 'list_codes':
            data = await httpClient.get('/api/exceptions/list_codes');
            break;
          case 'skip':
            data = await httpClient.post('/api/exceptions/skip');
            break;
          case 'seh_chain':
            data = await httpClient.get('/api/exceptions/seh_chain');
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
