import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerIndirectSyscallAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_indirect_syscall_analyzer',
    "Direct & Indirect Syscall Stub Analyzer. Detect SysWhispers, Hell's Gate, Halo's Gate, FreshyCalls patterns, resolve SSNs, and unhook verification.",
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('scan_stubs'),
          start_address: z.string().optional().describe('Start address to scan (defaults to main module)'),
          size: z.number().optional().describe('Scan range size in bytes'),
          pattern_type: z.string().optional().describe('Filter pattern: all, direct, indirect')
        }),
        z.object({
          action: z.literal('resolve_ssn'),
          function_name: z.string().describe('NT API function name (e.g. "NtAllocateVirtualMemory")')
        }),
        z.object({
          action: z.literal('unhook_verify')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'scan_stubs':
            data = await httpClient.post('/api/syscall_stub/scan', {
              start_address: action.start_address,
              size: action.size,
              pattern_type: action.pattern_type
            });
            break;
          case 'resolve_ssn':
            data = await httpClient.post('/api/syscall_stub/resolve_ssn', {
              function_name: action.function_name
            });
            break;
          case 'unhook_verify':
            data = await httpClient.post('/api/syscall_stub/unhook_verify', {});
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
