import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemwatchTools(server: McpServer) {
  server.tool(
    'memwatch_snapshot',
    'Take a named memory snapshot of an address range. Use this before and after an action ' +
    'to diff what changed. Requires debugger to be paused.',
    {
      name:    z.string().max(64).describe('Snapshot name (e.g. "before_call", "after_patch")'),
      address: z.string().describe('Start address of the memory region to snapshot'),
      size:    z.number().int().min(1).max(67108864).describe('Number of bytes to snapshot (max 64MB)'),
    },
    async ({ name, address, size }) => {
      const data = await httpClient.post('/api/memwatch/snapshot', { name, address, size });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'memwatch_list',
    'List all saved memory snapshots with their names, addresses, sizes, and timestamps.',
    {},
    async () => {
      const data = await httpClient.get('/api/memwatch/list');
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'memwatch_diff',
    'Byte-level diff two named memory snapshots. Both must have the same base address. ' +
    'Returns changed byte regions as {offset, address, before, after, size} records.',
    {
      a:     z.string().describe('Name of the first (before) snapshot'),
      b:     z.string().describe('Name of the second (after) snapshot'),
      limit: z.number().int().min(1).max(100000).optional().default(1000)
              .describe('Maximum number of changed regions to return'),
    },
    async ({ a, b, limit }) => {
      const data = await httpClient.post('/api/memwatch/diff', { a, b, limit });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'memwatch_watch_region',
    'One-shot memory watcher: snapshots a region BEFORE an execution trigger, ' +
    'executes the trigger (step_into/step_over/run), snapshots AFTER, and returns the diff. ' +
    'Perfect for observing what a single function call writes to memory.',
    {
      name:    z.string().optional().default('watch_region').describe('Region name label'),
      address: z.string().describe('Start address of the region to watch'),
      size:    z.number().int().min(1).max(67108864).describe('Number of bytes to watch'),
      trigger: z.enum(['step_into', 'step_over', 'run'])
                .optional().default('step_over')
                .describe('Execution trigger to apply after taking the before snapshot'),
      wait_ms: z.number().int().min(0).max(60000).optional().default(10000)
                .describe('Timeout in ms to wait for the debugger to pause after trigger'),
    },
    async ({ name, address, size, trigger, wait_ms }) => {
      const data = await httpClient.post('/api/memwatch/watch_region', {
        name, address, size, trigger, wait_ms,
      });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'memwatch_delete',
    'Delete a named memory snapshot to free memory.',
    {
      name: z.string().describe('Snapshot name to delete'),
    },
    async ({ name }) => {
      const data = await httpClient.post('/api/memwatch/delete', { name });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
