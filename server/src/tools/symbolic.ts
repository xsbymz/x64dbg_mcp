import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSymbolicTools(server: McpServer) {
  server.tool(
    'x64dbg_symbolic',
    'Symbolic execution helpers: extract path constraints, solve constraints, track taint propagation, and explore alternative execution paths.',
    {
      action: z.enum(['constraints', 'solve', 'taint_propagation', 'path_exploration']).describe('Symbolic analysis type'),
      address: z.string().optional().describe('Memory address or expression'),
      depth: z.number().optional().default(10).describe('Lookback depth for constraints'),
      size: z.string().optional().describe('Memory size (taint_propagation action)'),
      max_paths: z.number().optional().default(10).describe('Maximum paths to explore'),
      constraints: z.any().optional().describe('Array of constraints to solve (solve action)')
    },
    async ({ action, address, depth, size, max_paths, constraints }) => {
      try {
        let data: unknown;
        const params: Record<string, string> = {};

        switch (action) {
          case 'constraints':
            data = await httpClient.post('/api/symbolic/constraints', {
              address: address || 'cip',
              depth
            });
            break;
          case 'solve':
            data = await httpClient.post('/api/symbolic/solve', {
              constraints: constraints || []
            });
            break;
          case 'taint_propagation':
            data = await httpClient.get('/api/symbolic/taint_propagation', {
              address: address || 'cip',
              size: size || '256'
            });
            break;
          case 'path_exploration':
            data = await httpClient.post('/api/symbolic/path_exploration', {
              address: address || 'cip',
              max_paths
            });
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
