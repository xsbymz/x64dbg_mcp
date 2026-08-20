import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerInmemorySnapshotHarnessTools(server: McpServer) {
  server.tool(
    'x64dbg_inmemory_snapshot_harness',
    'Rapid in-memory delta snapshot checkpointing, register context saving, and sub-millisecond state rollback micro-fuzzing harness.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('create_checkpoint')
        }),
        z.object({
          action: z.literal('revert_checkpoint')
        }),
        z.object({
          action: z.literal('run_iteration')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'create_checkpoint':
            data = await httpClient.post('/api/snapshot_harness/create_checkpoint', {});
            break;
          case 'revert_checkpoint':
            data = await httpClient.post('/api/snapshot_harness/revert_checkpoint', {});
            break;
          case 'run_iteration':
            data = await httpClient.post('/api/snapshot_harness/run_iteration', {});
            break;
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
