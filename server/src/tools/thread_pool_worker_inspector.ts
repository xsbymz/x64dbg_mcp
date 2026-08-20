import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerThreadPoolWorkerInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_thread_pool_worker_inspector',
    'Enumerate Win32 ThreadPool workers (PTP_POOL, PTP_CLEANUP_GROUP, PTP_WORK, PTP_TIMER, and pending callback queues).',
    {
      action: z.enum(['list_thread_pools', 'list_work_callbacks', 'get_timer_queues']).describe('Thread pool action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'list_thread_pools':
          data = await httpClient.get('/api/thread_pool/list');
          break;
        case 'list_work_callbacks':
          data = await httpClient.get('/api/thread_pool/callbacks');
          break;
        case 'get_timer_queues':
          data = await httpClient.get('/api/thread_pool/timers');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
