import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSehHandlerDispatcherSimTools(server: McpServer) {
  server.tool(
    'x64dbg_seh_handler_dispatcher_sim',
    'Simulate RtlDispatchException search phase, frame handler evaluation order, and unwinding passes across all active stack frames.',
    {
      action: z.enum(['simulate_dispatch', 'get_dispatch_order', 'check_collided_unwind']).describe('Dispatcher simulation action'),
      exception_code: z.number().default(0xC0000005).describe('Synthetic NTSTATUS exception code'),
    },
    async ({ action, exception_code }) => {
      let data: unknown;
      switch (action) {
        case 'simulate_dispatch':
          data = await httpClient.post('/api/rtl_dispatch/simulate', { exception_code });
          break;
        case 'get_dispatch_order':
          data = await httpClient.post('/api/rtl_dispatch/order', { exception_code });
          break;
        case 'check_collided_unwind':
          data = await httpClient.get('/api/rtl_dispatch/collided');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
