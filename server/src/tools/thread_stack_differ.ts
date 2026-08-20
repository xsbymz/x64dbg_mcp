import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerThreadStackDifferTools(server: McpServer) {
  server.tool(
    'x64dbg_thread_stack_differ',
    'Capture and diff thread call stacks over execution intervals to detect hung threads, worker thread state transitions, and deadlock conditions.',
    {
      action: z.enum(['snapshot_all_threads', 'diff_with_previous', 'detect_deadlocks', 'list_blocked_threads']).describe('Thread diff action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'snapshot_all_threads':
          data = await httpClient.get('/api/threads/diff/snapshot');
          break;
        case 'diff_with_previous':
          data = await httpClient.get('/api/threads/diff/compare');
          break;
        case 'detect_deadlocks':
          data = await httpClient.get('/api/threads/diff/deadlocks');
          break;
        case 'list_blocked_threads':
          data = await httpClient.get('/api/threads/diff/blocked');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
