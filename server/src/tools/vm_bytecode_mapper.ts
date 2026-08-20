import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerVmBytecodeMapperTools(server: McpServer) {
  server.tool(
    'x64dbg_vm_bytecode_mapper',
    'Virtual Machine & Bytecode Dispatch Table Deobfuscator. Find central VM dispatch loops, map virtual opcode handlers, and trace interpreted bytecode execution.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('find_dispatcher')
        }),
        z.object({
          action: z.literal('map_handlers'),
          table_address: z.string().describe('VM handler table address (e.g. "0x408000")'),
          handler_count: z.number().optional().describe('Number of handler slots to dissect')
        }),
        z.object({
          action: z.literal('trace_bytecode')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'find_dispatcher':
            data = await httpClient.post('/api/vm_bytecode/find_dispatcher', {});
            break;
          case 'map_handlers':
            data = await httpClient.post('/api/vm_bytecode/map_handlers', {
              table_address: action.table_address,
              handler_count: action.handler_count
            });
            break;
          case 'trace_bytecode':
            data = await httpClient.post('/api/vm_bytecode/trace_bytecode', {});
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
