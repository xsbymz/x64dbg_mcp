import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSnapshotTools(server: McpServer) {
  server.tool(
    'x64dbg_snapshot',
    'Cheat Engine-style memory snapshot and differential scanner. ' +
    'Take a memory snapshot, step the debugger, and compare memory values to find dynamically allocated structures, flags, counters, or decryptor buffers. ' +
    'Actions: create (capture snapshot of memory range), diff (compare snapshot vs live memory for changed, unchanged, increased, decreased values), list (list existing snapshots).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('create'),
          name: z.string().optional().default('default').describe('Unique name for the snapshot'),
          address: z.string().describe('Base address to capture (hex or expression)'),
          size: z.string().describe('Size in bytes (hex or decimal, max 64MB)')
        }),
        z.object({
          action: z.literal('diff'),
          name: z.string().optional().default('default').describe('Snapshot name to compare against'),
          filter: z.enum(['changed', 'unchanged', 'increased', 'decreased']).optional().default('changed').describe('Comparison filter'),
          value_type: z.enum(['u8', 'u16', 'u32', 'u64']).optional().default('u32').describe('Value integer type'),
          max_results: z.number().optional().default(500).describe('Max match results to return')
        }),
        z.object({
          action: z.literal('list')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'create':
            data = await httpClient.post('/api/memory/snapshot', {
              name: action.name,
              address: action.address,
              size: action.size
            });
            break;
          case 'diff':
            data = await httpClient.post('/api/memory/diff', {
              name: action.name,
              filter: action.filter,
              value_type: action.value_type,
              max_results: action.max_results
            });
            break;
          case 'list':
            data = await httpClient.get('/api/memory/snapshots');
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
