import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerThreadSynchronizationWaitChainWalkerTools(server: McpServer) {
  server.tool(
    'x64dbg_thread_synchronization_wait_chain_walker',
    'Walk Windows Wait Chain Traversal (WCT) trees to diagnose thread blocking, lock hierarchies, and cross-process deadlock cycles.',
    {
      action: z.enum(['walk_wait_chain', 'detect_deadlock_cycles', 'list_blocking_objects']).describe('Wait chain action'),
      thread_id: z.number().optional().describe('Target thread ID (defaults to current thread)'),
    },
    async ({ action, thread_id }) => {
      let data: unknown;
      switch (action) {
        case 'walk_wait_chain':
          data = await httpClient.post('/api/wct_walk/walk', { thread_id });
          break;
        case 'detect_deadlock_cycles':
          data = await httpClient.get('/api/wct_walk/deadlocks');
          break;
        case 'list_blocking_objects':
          data = await httpClient.get('/api/wct_walk/objects');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
