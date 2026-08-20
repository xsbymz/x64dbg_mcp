import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerBranchTargetTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_branch_target_tracer',
    'Record taken branch destinations, indirect call targets, and computed jump paths into a circular trace buffer.',
    {
      action: z.enum(['start_branch_trace', 'stop_branch_trace', 'get_recorded_branches']).describe('Branch trace action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'start_branch_trace':
          data = await httpClient.post('/api/branch_tracer/start', {});
          break;
        case 'stop_branch_trace':
          data = await httpClient.post('/api/branch_tracer/stop', {});
          break;
        case 'get_recorded_branches':
          data = await httpClient.get('/api/branch_tracer/branches');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
