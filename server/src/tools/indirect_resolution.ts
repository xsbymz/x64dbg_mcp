import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerIndirectResolutionTools(server: McpServer) {
  server.tool(
    'x64dbg_indirect_resolution',
    'Resolve indirect calls and jumps to enable complete control flow graph analysis. ' +
    'Analyzes VTables, function pointers, virtual dispatch, and computed branch targets. ' +
    'Actions: resolve_vtable (resolve C++ VTable calls), resolve_indirect (find all possible call targets), ' +
    'resolve_jump_table (analyze switch/dispatch tables), complete_cfg (build complete CFG with resolutions).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('resolve_vtable'),
          address: z.string().describe('VTable address (hex or expression)'),
          class_name: z.string().optional().describe('C++ class name (optional hint)'),
          include_overrides: z.boolean().optional().default(true).describe('Include virtual function overrides')
        }),
        z.object({
          action: z.literal('resolve_indirect'),
          address: z.string().describe('Instruction with indirect call/jmp (hex or expression)'),
          depth: z.number().optional().default(5).describe('Data flow analysis depth'),
          max_targets: z.number().optional().default(20).describe('Maximum targets to enumerate')
        }),
        z.object({
          action: z.literal('resolve_jump_table'),
          address: z.string().describe('Switch/dispatch table address'),
          entry_count: z.number().optional().describe('Number of entries (or auto-detect)'),
          entry_size: z.number().optional().default(4).describe('Bytes per entry (4 or 8)')
        }),
        z.object({
          action: z.literal('complete_cfg'),
          function: z.string().describe('Function address to analyze'),
          resolve_all_indirects: z.boolean().optional().default(true).describe('Resolve all indirect branches'),
          show_unreachable: z.boolean().optional().default(true).describe('Show unreachable blocks')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'resolve_vtable':
            data = await httpClient.post('/api/indirect/resolve_vtable', {
              address: action.address,
              class_name: action.class_name,
              include_overrides: action.include_overrides
            });
            break;
          case 'resolve_indirect':
            data = await httpClient.post('/api/indirect/resolve_indirect', {
              address: action.address,
              depth: action.depth,
              max_targets: action.max_targets
            });
            break;
          case 'resolve_jump_table':
            data = await httpClient.post('/api/indirect/resolve_jump_table', {
              address: action.address,
              entry_count: action.entry_count,
              entry_size: action.entry_size
            });
            break;
          case 'complete_cfg':
            data = await httpClient.post('/api/indirect/complete_cfg', {
              function: action.function,
              resolve_all_indirects: action.resolve_all_indirects,
              show_unreachable: action.show_unreachable
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
