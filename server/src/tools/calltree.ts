import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCallTreeTools(server: McpServer) {
  server.tool(
    'calltree_from',
    'Build a recursive call graph starting from a function. ' +
    'Walks all CALL instructions in each function and follows them to the specified depth. ' +
    'Returns either a flat list of nodes or a nested tree (use nested=true for AI readability). ' +
    'Flags recursive and cross-module (external) calls.',
    {
      address:          z.string().optional().default('cip')
                         .describe('Root function address (default: function at CIP)'),
      depth:            z.number().int().min(1).max(10).optional().default(3)
                         .describe('Maximum call depth to explore'),
      max_nodes:        z.number().int().min(1).max(5000).optional().default(500)
                         .describe('Maximum total number of nodes (functions) to include'),
      include_external: z.boolean().optional().default(false)
                         .describe('If true, follow calls into other modules (e.g. kernel32.dll)'),
      nested:           z.boolean().optional().default(true)
                         .describe('If true, return a nested tree; if false, return a flat node list'),
    },
    async ({ address, depth, max_nodes, include_external, nested }) => {
      const data = await httpClient.get('/api/calltree/from', {
        address: address ?? 'cip',
        depth: String(depth),
        max_nodes: String(max_nodes),
        include_external: String(include_external),
        nested: String(nested),
      });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'calltree_loops',
    'Detect recursive and mutually-recursive calls (back edges) in the call graph. ' +
    'Reports the "from" and "to" functions for each back edge, ' +
    'and classifies them as self_recursion or mutual_recursion.',
    {
      address:   z.string().optional().default('cip')
                  .describe('Root function address'),
      depth:     z.number().int().min(1).max(8).optional().default(4)
                  .describe('Maximum depth of call graph to analyse'),
      max_nodes: z.number().int().min(1).max(5000).optional().default(1000),
    },
    async ({ address, depth, max_nodes }) => {
      const data = await httpClient.get('/api/calltree/loop_detect', {
        address: address ?? 'cip',
        depth: String(depth),
        max_nodes: String(max_nodes),
      });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'calltree_export',
    'Export the call graph in a visualisable format. ' +
    'dot: paste into https://dreampuf.github.io/GraphvizOnline  ' +
    'mermaid: paste into https://mermaid.live  ' +
    'json: structured flat node list',
    {
      address:   z.string().optional().default('cip').describe('Root function address'),
      depth:     z.number().int().min(1).max(8).optional().default(3),
      max_nodes: z.number().int().min(1).max(5000).optional().default(500),
      format:    z.enum(['dot', 'mermaid', 'json']).optional().default('dot'),
    },
    async ({ address, depth, max_nodes, format }) => {
      const data = await httpClient.post('/api/calltree/export', {
        address, depth, max_nodes, format,
      });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'calltree_dominators',
    'Compute a simplified immediate dominator tree for the call graph. ' +
    'For each function reachable from the root, returns its immediate dominator ' +
    '(the function that must always be called before it). ' +
    'Useful for understanding required call paths and finding unreachable code.',
    {
      address:   z.string().optional().default('cip').describe('Root function address'),
      depth:     z.number().int().min(1).max(6).optional().default(4),
    },
    async ({ address, depth }) => {
      const data = await httpClient.get('/api/calltree/dominators', {
        address: address ?? 'cip',
        depth: String(depth),
      });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
