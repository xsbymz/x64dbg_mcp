import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerNtdllSyscallTableDumpTools(server: McpServer) {
  server.tool(
    'x64dbg_ntdll_syscall_table_dump',
    'Dump the entire user-mode NTDLL system call table with System Service Numbers (SSNs), function RVAs, and export ordinals across Windows OS builds.',
    {
      action: z.enum(['dump_all_syscalls', 'lookup_syscall_by_ssn', 'lookup_syscall_by_name']).describe('Syscall table action'),
      ssn: z.number().optional().describe('System service number (e.g. 0x0018 for NtAllocateVirtualMemory)'),
      name: z.string().optional().describe('Syscall export name (e.g. NtProtectVirtualMemory)'),
    },
    async ({ action, ssn, name }) => {
      let data: unknown;
      switch (action) {
        case 'dump_all_syscalls':
          data = await httpClient.get('/api/ntdll_syscalls/all');
          break;
        case 'lookup_syscall_by_ssn':
          data = await httpClient.post('/api/ntdll_syscalls/by_ssn', { ssn });
          break;
        case 'lookup_syscall_by_name':
          data = await httpClient.post('/api/ntdll_syscalls/by_name', { name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
