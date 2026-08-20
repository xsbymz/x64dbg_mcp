import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCrashBackwardSlicerTools(server: McpServer) {
  server.tool(
    'x64dbg_crash_backward_slicer',
    'Automated backward data-flow slicing engine to reconstruct operand dependency DAGs from faulting instructions to input buffer sources.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('slice_faulting_instruction')
        }),
        z.object({
          action: z.literal('trace_operand_dependencies'),
          register: z.string().optional()
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'slice_faulting_instruction':
            data = await httpClient.post('/api/slicer/slice_faulting_instruction', {});
            break;
          case 'trace_operand_dependencies':
            data = await httpClient.post('/api/slicer/trace_operand_dependencies', {
              register: action.register
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
