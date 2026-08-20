import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerTelemetryTools(server: McpServer) {
  server.tool(
    'x64dbg_telemetry',
    'Automated Windows API telemetry and behavioral monitoring hooks. ' +
    'Set up categorized logging breakpoints on critical Windows APIs to observe dropper behavior, C2 sockets, registry persistence, process injection, or anti-debug checks. ' +
    'Actions: enable (set automated logging hooks for a category), disable (remove telemetry hooks).',
    {
      action: z.enum(['enable', 'disable']).describe('enable or disable telemetry'),
      category: z.enum(['all', 'file_io', 'registry', 'injection', 'network', 'anti_debug']).optional().default('all').describe(
        'Target API category to monitor: file_io (CreateFile, WriteFile, DeleteFile), registry (RegOpenKey, RegSetValue), injection (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread), network (InternetOpen, connect, send), anti_debug (IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess), or all'
      ),
      break_on_call: z.boolean().optional().default(false).describe(
        'If true, pauses the debugger when the API is hit. If false (default), runs silently and logs calls to x64dbg log.'
      )
    },
    async ({ action, category, break_on_call }) => {
      try {
        let data: unknown;
        if (action === 'enable') {
          data = await httpClient.post('/api/telemetry/enable', { category, break_on_call });
        } else {
          data = await httpClient.post('/api/telemetry/disable', { category });
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
