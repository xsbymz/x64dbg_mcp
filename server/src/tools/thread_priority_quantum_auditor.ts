import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerThreadPriorityQuantumAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_thread_priority_quantum_auditor',
    'Audit thread dynamic priorities, priority boost disables (THREAD_PRIORITY_BOOST), base priorities, and thread quantum starvation states.',
    {
      action: z.enum(['audit_thread_priorities', 'set_thread_priority', 'check_starvation']).describe('Thread priority action'),
      thread_id: z.number().optional().describe('Target Thread ID'),
      priority_level: z.number().optional().describe('New priority level (-15 to 15, or THREAD_PRIORITY_TIME_CRITICAL)'),
    },
    async ({ action, thread_id, priority_level }) => {
      let data: unknown;
      switch (action) {
        case 'audit_thread_priorities':
          data = await httpClient.get('/api/thread_priority/audit');
          break;
        case 'set_thread_priority':
          data = await httpClient.post('/api/thread_priority/set', { thread_id, priority_level });
          break;
        case 'check_starvation':
          data = await httpClient.get('/api/thread_priority/starvation');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
