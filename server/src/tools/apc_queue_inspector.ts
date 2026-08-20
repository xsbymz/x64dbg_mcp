import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerApcQueueInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_apc_queue_inspector',
    'Inspect thread Asynchronous Procedure Call (APC) queues: enumerate queued user-mode APC routines, arguments, and alertable wait states (QueueUserAPC/NtQueueApcThread).',
    {
      action: z.enum(['list_thread_apcs', 'inspect_all_queues', 'check_alertable_threads']).describe('APC queue action'),
      thread_id: z.number().optional().describe('Target thread ID (defaults to active thread)'),
    },
    async ({ action, thread_id }) => {
      let data: unknown;
      switch (action) {
        case 'list_thread_apcs':
          data = await httpClient.post('/api/apc/thread_queue', { thread_id });
          break;
        case 'inspect_all_queues':
          data = await httpClient.get('/api/apc/all_queues');
          break;
        case 'check_alertable_threads':
          data = await httpClient.get('/api/apc/alertable_threads');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
