import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerInstructionBranchRunlengthProfilerTools(server: McpServer) {
  server.tool(
    'x64dbg_instruction_branch_runlength_profiler',
    'Profile run-lengths of taken vs non-taken consecutive branches in loops to calculate branch entropy and predictability.',
    {
      action: z.enum(['profile_runlengths', 'get_loop_trip_counts', 'get_branch_entropy']).describe('Branch runlength action'),
      branch_address: z.string().optional().describe('Virtual address of branch instruction'),
    },
    async ({ action, branch_address }) => {
      let data: unknown;
      switch (action) {
        case 'profile_runlengths':
          data = await httpClient.post('/api/branch_runlength/profile', { branch_address });
          break;
        case 'get_loop_trip_counts':
          data = await httpClient.post('/api/branch_runlength/trips', { branch_address });
          break;
        case 'get_branch_entropy':
          data = await httpClient.post('/api/branch_runlength/entropy', { branch_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
