import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerBranchCoverageTools(server: McpServer) {
  server.tool(
    'x64dbg_branch_coverage',
    'Track and analyze code path coverage and branch execution. Find uncovered branches, analyze code reachability, and identify dead code paths. ' +
    'Actions: start_trace (begin coverage tracking), get_coverage (current coverage report), find_dead_code (identify unreachable code), ' +
    'analyze_branches (branch execution analysis).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('start_trace'),
          reset: z.boolean().optional().default(true).describe('Clear previous coverage data'),
          track_module: z.string().optional().describe('Restrict tracking to specific module')
        }),
        z.object({
          action: z.literal('get_coverage'),
          module: z.string().optional().describe('Get coverage for specific module (all if omitted)'),
          format: z.enum(['summary', 'detailed', 'by_function']).optional().default('summary').describe('Report format')
        }),
        z.object({
          action: z.literal('find_dead_code'),
          module: z.string().optional().describe('Scan module for dead code'),
          min_block_size: z.number().optional().default(8).describe('Minimum basic block size to report'),
          include_unreachable: z.boolean().optional().default(true).describe('Include unreachable sections')
        }),
        z.object({
          action: z.literal('analyze_branches'),
          address: z.string().optional().describe('Function address to analyze (or current CIP if omitted)'),
          show_probability: z.boolean().optional().default(true).describe('Show branch probabilities'),
          show_frequency: z.boolean().optional().default(true).describe('Show execution frequency')
        }),
        z.object({
          action: z.literal('stop_trace')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'start_trace':
            data = await httpClient.post('/api/coverage/start', {
              reset: action.reset,
              track_module: action.track_module
            });
            break;
          case 'get_coverage':
            data = await httpClient.get('/api/coverage/report', {
              module: action.module || '',
              format: action.format
            });
            break;
          case 'find_dead_code':
            data = await httpClient.post('/api/coverage/find_dead_code', {
              module: action.module,
              min_block_size: action.min_block_size,
              include_unreachable: action.include_unreachable
            });
            break;
          case 'analyze_branches':
            data = await httpClient.post('/api/coverage/analyze_branches', {
              address: action.address,
              show_probability: action.show_probability,
              show_frequency: action.show_frequency
            });
            break;
          case 'stop_trace':
            data = await httpClient.post('/api/coverage/stop', {});
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
