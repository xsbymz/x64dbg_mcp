import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerProcessTreeSnapshotterTools(server: McpServer) {
  server.tool(
    'x64dbg_process_tree_snapshotter',
    'Capture the full system process hierarchy tree, parent-child process lineages, orphan processes, and PID spoofing anomalies.',
    {
      action: z.enum(['snapshot_process_tree', 'get_parent_lineage', 'detect_orphaned_processes']).describe('Process tree action'),
      pid: z.number().optional().describe('Target process ID (defaults to current debuggee)'),
    },
    async ({ action, pid }) => {
      let data: unknown;
      switch (action) {
        case 'snapshot_process_tree':
          data = await httpClient.get('/api/proc_tree/snapshot');
          break;
        case 'get_parent_lineage':
          data = await httpClient.post('/api/proc_tree/lineage', { pid });
          break;
        case 'detect_orphaned_processes':
          data = await httpClient.get('/api/proc_tree/orphans');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
