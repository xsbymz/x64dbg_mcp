import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSyscallTools(server: McpServer) {
  server.tool(
    'x64dbg_syscalls',
    'NTDLL/Kernel32 syscall enumeration, SSN extraction, and hook detection. ' +
    'Actions: ntdll (enumerate NTDLL exports with syscall IDs and hook status), ' +
    'ssn (get syscall ID for a specific NTDLL export by name), ' +
    'hooks (compare NTDLL syscall stubs against clean patterns to detect inline hooks), ' +
    'kernel32 (enumerate Kernel32 exports with inline hook detection).',
    {
      action: z.enum(['ntdll', 'ssn', 'hooks', 'kernel32']).describe('Syscall action'),
      name: z.string().optional().describe('NTDLL export name (required for ssn action)')
    },
    async ({ action, name }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'ntdll':
            data = await httpClient.get('/api/syscalls/ntdll');
            break;
          case 'ssn':
            if (!name) throw new Error('name is required for ssn action');
            data = await httpClient.get('/api/syscalls/ssn', { name });
            break;
          case 'hooks':
            data = await httpClient.get('/api/syscalls/hooks');
            break;
          case 'kernel32':
            data = await httpClient.get('/api/syscalls/kernel32');
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
