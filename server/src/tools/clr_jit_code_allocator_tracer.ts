import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerClrJitCodeAllocatorTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_clr_jit_code_allocator_tracer',
    'Trace .NET CLR JIT compiler execution memory allocations (EEJitManager, allocMem, JIT code heaps, and executable thunk stubs).',
    {
      action: z.enum(['list_jit_heaps', 'trace_jit_allocations', 'get_active_code_manager']).describe('JIT tracer action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'list_jit_heaps':
          data = await httpClient.get('/api/clr_jit/heaps');
          break;
        case 'trace_jit_allocations':
          data = await httpClient.get('/api/clr_jit/allocations');
          break;
        case 'get_active_code_manager':
          data = await httpClient.get('/api/clr_jit/manager');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
