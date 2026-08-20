import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPrivescTools(server: McpServer) {
  server.tool(
    'x64dbg_privesc',
    'Privilege escalation analysis and UAC bypass detection. Identify token theft opportunities, UAC bypass vectors, and kernel exploitation paths. ' +
    'Actions: analyze_tokens (inspect process tokens), find_uac_bypasses (detect UAC bypass vectors), find_kernel_paths (identify kernel-mode entry points).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('analyze_tokens'),
          process_id: z.string().optional().describe('Process ID to analyze (current if omitted)'),
          include_impersonation: z.boolean().optional().default(true).describe('Include impersonation tokens'),
          check_privileges: z.boolean().optional().default(true).describe('Check privilege status')
        }),
        z.object({
          action: z.literal('find_uac_bypasses'),
          method: z.enum(['token_duplication', 'elevated_process', 'cmstplua', 'fodhelper', 'eventvwr', 'all']).optional().default('all').describe('Specific bypass to check or all'),
          check_writeable_paths: z.boolean().optional().default(true).describe('Find writeable directories used by UAC bypass vectors')
        }),
        z.object({
          action: z.literal('find_kernel_paths'),
          check_syscalls: z.boolean().optional().default(true).describe('Check syscall availability'),
          check_drivers: z.boolean().optional().default(true).describe('Check for vulnerable drivers'),
          include_token_theft: z.boolean().optional().default(true).describe('Identify token theft gadgets')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'analyze_tokens':
            data = await httpClient.post('/api/privesc/analyze_tokens', {
              process_id: action.process_id,
              include_impersonation: action.include_impersonation,
              check_privileges: action.check_privileges
            });
            break;
          case 'find_uac_bypasses':
            data = await httpClient.post('/api/privesc/find_uac_bypasses', {
              method: action.method,
              check_writeable_paths: action.check_writeable_paths
            });
            break;
          case 'find_kernel_paths':
            data = await httpClient.post('/api/privesc/find_kernel_paths', {
              check_syscalls: action.check_syscalls,
              check_drivers: action.check_drivers,
              include_token_theft: action.include_token_theft
            });
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
