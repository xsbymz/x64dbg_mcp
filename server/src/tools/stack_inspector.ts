import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerStackInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_stack_inspector',
    'Deep stack frame analysis and parameter parsing. Inspect call stacks with automatic calling convention detection and parameter interpretation. ' +
    'Actions: inspect_frame (detailed frame analysis), unwind_stack (full call stack), parse_parameters (extract function parameters from registers/stack).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('inspect_frame'),
          frame_index: z.number().optional().default(0).describe('Stack frame index (0=current, 1=caller, etc)'),
          include_locals: z.boolean().optional().default(true).describe('Include local variables'),
          include_params: z.boolean().optional().default(true).describe('Include function parameters'),
          include_saved_regs: z.boolean().optional().default(true).describe('Include saved registers')
        }),
        z.object({
          action: z.literal('unwind_stack'),
          max_depth: z.number().optional().default(20).describe('Maximum frames to return'),
          resolve_symbols: z.boolean().optional().default(true).describe('Resolve function names'),
          include_args: z.boolean().optional().default(true).describe('Include function arguments')
        }),
        z.object({
          action: z.literal('parse_parameters'),
          address: z.string().describe('Function address or current instruction'),
          tid: z.string().optional().describe('Thread ID (current if omitted)'),
          calling_convention: z.enum(['x64', 'stdcall', 'fastcall', 'cdecl']).optional().describe('Calling convention (auto-detect if omitted)'),
          param_count: z.number().optional().default(4).describe('Number of parameters to extract')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'inspect_frame':
            data = await httpClient.post('/api/stack/inspect_frame', {
              frame_index: action.frame_index,
              include_locals: action.include_locals,
              include_params: action.include_params,
              include_saved_regs: action.include_saved_regs
            });
            break;
          case 'unwind_stack':
            data = await httpClient.get('/api/stack/unwind', {
              max_depth: String(action.max_depth),
              resolve_symbols: String(action.resolve_symbols),
              include_args: String(action.include_args)
            });
            break;
          case 'parse_parameters':
            data = await httpClient.post('/api/stack/parse_parameters', {
              address: action.address,
              tid: action.tid,
              calling_convention: action.calling_convention,
              param_count: action.param_count
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
