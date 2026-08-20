import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAntiDebugTools(server: McpServer) {
  server.tool(
    'x64dbg_antidebug',
    'Anti-debugging analysis, evasion, and user-mode hook auditing: Audit process stealthiness, inspect API/syscall hooks, inspect PEB/TEB/DEP, or hide debugger flags. ' +
    'Actions: audit (comprehensive anti-debug detection check on PEB.BeingDebugged, NtGlobalFlag, hardware BPs, and DEP), ' +
    'hooks (audit critical NTDLL / Kernel32 APIs for inline JMP detours, trampolines, INT3 breakpoints, and EDR interception), ' +
    'peb (inspect PEB BeingDebugged & NtGlobalFlag), teb (inspect TEB SEH pointer), dep (check DEP status), hide_debugger (zero BeingDebugged and NtGlobalFlag).',
    {
      action: z.discriminatedUnion("action", [
        z.object({ action: z.literal("audit") }),
        z.object({ action: z.literal("hooks") }),
        z.object({ action: z.literal("peb"), pid: z.string().optional() }),
        z.object({ action: z.literal("teb"), tid: z.string().optional() }),
        z.object({ action: z.literal("dep") }),
        z.object({ action: z.literal("hide_debugger") })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'audit':
            data = await httpClient.get('/api/antidebug/audit');
            break;
          case 'hooks':
            data = await httpClient.get('/api/antidebug/hooks');
            break;
          case 'peb':
            data = await httpClient.get('/api/antidebug/peb', { pid: action.pid || '' });
            break;
          case 'teb':
            data = await httpClient.get('/api/antidebug/teb', { tid: action.tid || '' });
            break;
          case 'dep':
            data = await httpClient.get('/api/antidebug/dep_status');
            break;
          case 'hide_debugger':
            data = await httpClient.post('/api/antidebug/hide_debugger');
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
