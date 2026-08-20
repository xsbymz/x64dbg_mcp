import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWin32kSyscallAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_win32k_syscall_auditor',
    'Resolve Windows GUI Shadow SSDT (win32k.sys, win32kbase.sys, win32kfull.sys) system call numbers, dispatch stubs, and GDI/USER kernel interfaces.',
    {
      action: z.enum(['dump_win32k_syscalls', 'resolve_by_ssn', 'resolve_by_name']).describe('Win32k action'),
      ssn: z.number().optional().describe('Win32k System Service Number (e.g. 0x1000 + index)'),
      name: z.string().optional().describe('Win32k function name (e.g. NtUserSetWindowsHookEx)'),
    },
    async ({ action, ssn, name }) => {
      let data: unknown;
      switch (action) {
        case 'dump_win32k_syscalls':
          data = await httpClient.get('/api/win32k_syscalls/all');
          break;
        case 'resolve_by_ssn':
          data = await httpClient.post('/api/win32k_syscalls/by_ssn', { ssn });
          break;
        case 'resolve_by_name':
          data = await httpClient.post('/api/win32k_syscalls/by_name', { name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
