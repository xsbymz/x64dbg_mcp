import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAutoAnnotateTools(server: McpServer) {
  server.tool(
    'annotate_function',
    'One-shot auto-annotator for a single function. Walks every instruction and: ' +
    '(1) comments CALL sites with the target symbol name, ' +
    '(2) comments LEA/MOV instructions that load string pointers with the string preview, ' +
    '(3) labels unnamed jump targets as j_<addr>, ' +
    '(4) marks indirect calls as vtbl_call_<addr>. ' +
    'Returns counts of each annotation type added.',
    {
      address:   z.string().optional().default('cip')
                  .describe('Function address to annotate (default: function containing CIP)'),
      overwrite: z.boolean().optional().default(false)
                  .describe('If true, overwrite existing comments/labels'),
    },
    async ({ address, overwrite }) => {
      const data = await httpClient.post('/api/annotate/function', { address, overwrite });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'annotate_module',
    'Annotate all functions in a module at once. Scans every function and applies the same ' +
    'annotations as annotate_function: call symbol comments, string pointer comments. ' +
    'May take 10-60s for large modules.',
    {
      module:        z.string().optional().describe('Module name (default: module at CIP)'),
      overwrite:     z.boolean().optional().default(false)
                      .describe('Overwrite existing comments'),
      max_functions: z.number().int().min(1).max(50000).optional().default(5000)
                      .describe('Maximum number of functions to annotate'),
    },
    async ({ module, overwrite, max_functions }) => {
      const data = await httpClient.post('/api/annotate/module', {
        module, overwrite, max_functions,
      });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'annotate_clear',
    'Remove auto-generated comments from a module, optionally filtering by a prefix.',
    {
      module: z.string().optional().describe('Module name (default: module at CIP)'),
      prefix: z.string().optional().default('')
               .describe('Only remove comments starting with this prefix. Empty = remove all.'),
    },
    async ({ module, prefix }) => {
      const data = await httpClient.post('/api/annotate/clear', { module, prefix });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'annotate_export',
    'Export all labels and comments in a module. ' +
    'Use format="json" for a structured list, or format="x64dbg_script" to get a script ' +
    'you can import into another x64dbg session.',
    {
      module: z.string().optional().describe('Module name (default: module at CIP)'),
      format: z.enum(['json', 'x64dbg_script']).optional().default('json'),
    },
    async ({ module, format }) => {
      const params: Record<string, string> = { format: format ?? 'json' };
      if (module) params.module = module;
      const data = await httpClient.get('/api/annotate/export', params);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
