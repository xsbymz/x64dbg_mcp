import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWow64CpuContextReaderTools(server: McpServer) {
  server.tool(
    'x64dbg_wow64_cpu_context_reader',
    'Read WOW64 32-bit WOW64_CONTEXT (EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP, EFLAGS) alongside 64-bit CPU register contexts.',
    {
      action: z.enum(['get_wow64_context', 'get_wow64_eip', 'get_wow64_stack_pointer']).describe('WOW64 context action'),
      thread_id: z.number().optional().describe('Thread ID (defaults to active thread)'),
    },
    async ({ action, thread_id }) => {
      let data: unknown;
      switch (action) {
        case 'get_wow64_context':
          data = await httpClient.post('/api/wow64_ctx/get', { thread_id });
          break;
        case 'get_wow64_eip':
          data = await httpClient.post('/api/wow64_ctx/eip', { thread_id });
          break;
        case 'get_wow64_stack_pointer':
          data = await httpClient.post('/api/wow64_ctx/esp', { thread_id });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
