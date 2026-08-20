import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryPointerDerereferenceChainTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_pointer_derereference_chain_tracer',
    'Trace nested pointer dereference chains (e.g. [[[RAX+0x10]+0x28]+0x8]) with memory protection checks and type inference.',
    {
      action: z.enum(['trace_pointer_chain', 'evaluate_nested_offsets', 'validate_chain_memory_access']).describe('Pointer chain action'),
      base_address: z.string().describe('Base pointer address or register name (e.g. RAX or 0x7FF70000)'),
      offsets: z.array(z.number()).describe('Array of hex/int offset displacements applied sequentially'),
    },
    async ({ action, base_address, offsets }) => {
      let data: unknown;
      switch (action) {
        case 'trace_pointer_chain':
          data = await httpClient.post('/api/ptr_chain/trace', { base_address, offsets });
          break;
        case 'evaluate_nested_offsets':
          data = await httpClient.post('/api/ptr_chain/evaluate', { base_address, offsets });
          break;
        case 'validate_chain_memory_access':
          data = await httpClient.post('/api/ptr_chain/validate', { base_address, offsets });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
