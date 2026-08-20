import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCodeCoverageTools(server: McpServer) {
  server.tool(
    'coverage_start',
    'Begin recording code coverage. Once started, use coverage_mark_hit after each step ' +
    'to register executed addresses, then call coverage_stop when done.',
    {},
    async () => {
      const data = await httpClient.post('/api/coverage/start', {});
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'coverage_stop',
    'Stop recording code coverage and return the total number of unique addresses hit.',
    {},
    async () => {
      const data = await httpClient.post('/api/coverage/stop', {});
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'coverage_mark_hit',
    'Register one or more executed instruction addresses in the coverage store. ' +
    'Call this after each step_into/step_over to build a coverage trace. ' +
    'If no addresses are provided, marks the current CIP.',
    {
      addresses: z.array(z.string())
                   .optional()
                   .describe('Array of addresses (hex strings) to mark as executed. Omit to use current CIP.'),
    },
    async ({ addresses }) => {
      const data = await httpClient.post('/api/coverage/mark_hit', { addresses });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'coverage_hits',
    'Get the set of all currently recorded instruction addresses. ' +
    'Returns up to `limit` addresses as hex strings.',
    {
      limit: z.number().int().min(1).max(500000).optional().default(50000)
               .describe('Maximum number of hit addresses to return'),
    },
    async ({ limit }) => {
      const data = await httpClient.get('/api/coverage/hits', { limit: String(limit) });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'coverage_snapshot',
    'Save the current coverage hit set as a named snapshot for later diffing.',
    {
      name: z.string().describe('Snapshot name (e.g. "before_patch", "run_1")'),
    },
    async ({ name }) => {
      const data = await httpClient.post('/api/coverage/snapshot', { name });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'coverage_diff',
    'Compare two named coverage snapshots. Returns addresses only in A, only in B, and in both. ' +
    'Useful for finding which new code paths were exercised between two runs.',
    {
      a: z.string().describe('First snapshot name'),
      b: z.string().describe('Second snapshot name'),
    },
    async ({ a, b }) => {
      const data = await httpClient.post('/api/coverage/diff', { a, b });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'coverage_export',
    'Export the current coverage data. ' +
    'Use format="drcov" to produce a binary .cov file loadable by Lighthouse (IDA/Binja). ' +
    'Use format="json" for a plain array of hex addresses. ' +
    'Optionally write to a file on disk.',
    {
      format:  z.enum(['drcov', 'json']).optional().default('json')
                .describe('Export format: drcov (for Lighthouse) or json'),
      file:    z.string().optional()
                .describe('Optional absolute output file path (e.g. C:\\cov\\run1.cov)'),
    },
    async ({ format, file }) => {
      const data = await httpClient.post('/api/coverage/export', { format, file });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'coverage_reset',
    'Clear all coverage data and snapshots.',
    {},
    async () => {
      const data = await httpClient.post('/api/coverage/reset', {});
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
