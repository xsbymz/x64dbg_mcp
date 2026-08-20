import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerThreadQuantumPriorityBoosterTools(server: McpServer) {
  server.tool(
    'x64dbg_thread_quantum_priority_booster',
    'Query and modify thread dynamic priority boost (SetThreadPriorityBoost), quantum length, and foreground boosting.',
    {
      action: z.enum(['get_priority_boost_state', 'enable_priority_boost', 'disable_priority_boost']).describe('Priority boost action'),
      thread_id: z.number().optional().describe('Thread ID (defaults to active thread)'),
    },
    async ({ action, thread_id }) => {
      let data: unknown;
      switch (action) {
        case 'get_priority_boost_state':
          data = await httpClient.post('/api/boost_toggle/get', { thread_id });
          break;
        case 'enable_priority_boost':
          data = await httpClient.post('/api/boost_toggle/enable', { thread_id });
          break;
        case 'disable_priority_boost':
          data = await httpClient.post('/api/boost_toggle/disable', { thread_id });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
