import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerThreadIdealProcessorAssignerTools(server: McpServer) {
  server.tool(
    'x64dbg_thread_ideal_processor_assigner',
    'Assign or query preferred ideal processor cores (SetThreadIdealProcessorEx) and NUMA node assignments for debuggee threads.',
    {
      action: z.enum(['get_ideal_processor', 'set_ideal_processor', 'list_all_thread_ideal_procs']).describe('Ideal processor action'),
      thread_id: z.number().optional().describe('Thread ID (defaults to active thread)'),
      group: z.number().default(0).describe('Processor group index'),
      processor_number: z.number().optional().describe('Core number within group'),
    },
    async ({ action, thread_id, group, processor_number }) => {
      let data: unknown;
      switch (action) {
        case 'get_ideal_processor':
          data = await httpClient.post('/api/ideal_proc/get', { thread_id });
          break;
        case 'set_ideal_processor':
          data = await httpClient.post('/api/ideal_proc/set', { thread_id, group, processor_number });
          break;
        case 'list_all_thread_ideal_procs':
          data = await httpClient.get('/api/ideal_proc/all');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
