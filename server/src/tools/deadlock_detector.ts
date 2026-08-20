import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDeadlockDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_deadlock_detector',
    'Detect synchronization deadlocks: analyze thread ownership graphs for Critical Sections, Mutexes, Semaphores, and Slim Reader/Writer (SRW) locks.',
    {
      action: z.enum(['scan_deadlocks', 'list_sync_objects', 'get_wait_chains']).describe('Deadlock detection action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'scan_deadlocks':
          data = await httpClient.get('/api/deadlock/scan');
          break;
        case 'list_sync_objects':
          data = await httpClient.get('/api/deadlock/sync_objects');
          break;
        case 'get_wait_chains':
          data = await httpClient.get('/api/deadlock/wait_chains');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
