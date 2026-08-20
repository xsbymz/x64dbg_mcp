import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPebTools(server: McpServer) {
  server.tool(
    'x64dbg_peb',
    'Full PEB/TEB/process parameter enumeration and inspection. ' +
    'Actions: full (complete PEB walk: BeingDebugged, NtGlobalFlag, ProcessHeap, LDR module lists, ImageBase, ProcessParameters, ActivationContextData, Token), ' +
    'ldr (enumerate PEB_LDR_DATA lists: InLoadOrder, InMemoryOrder, InInitializationOrder), ' +
    'cmdline (extract full command line from RTL_USER_PROCESS_PARAMETERS), ' +
    'env (extract environment block as key=value pairs), ' +
    'teb_full (complete TEB walk: SEH frame, stack base/limit/commit/reserved, PEB pointer, TLS, LastError, TID, PID).',
    {
      action: z.enum(['full', 'ldr', 'cmdline', 'env', 'teb_full']).describe('PEB/TEB action'),
      pid: z.string().optional().describe('Process ID (decimal, optional; defaults to debugged process)'),
      tid: z.string().optional().describe('Thread ID (decimal, optional; defaults to current thread)')
    },
    async ({ action, pid, tid }) => {
      try {
        let data: unknown;
        const params: Record<string, string> = {};
        if (pid) params.pid = pid;
        if (tid) params.tid = tid;

        switch (action) {
          case 'full':
            data = await httpClient.get('/api/peb/full', params);
            break;
          case 'ldr':
            data = await httpClient.get('/api/peb/ldr', params);
            break;
          case 'cmdline':
            data = await httpClient.get('/api/peb/cmdline', params);
            break;
          case 'env':
            data = await httpClient.get('/api/peb/env', params);
            break;
          case 'teb_full':
            data = await httpClient.get('/api/teb/full', params);
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
