import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHwStateInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_hw_state_inspector',
    'Inspect hardware debug registers (DR0-DR7), CET Shadow Stack Pointers (SSP), and AVX/AVX-512 extended register states (ZMM0-ZMM31).',
    {
      action: z.enum(['debug_registers', 'cet_status', 'avx512_state']).describe('Hardware state category to query'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'debug_registers':
          data = await httpClient.get('/api/hw/debug_registers');
          break;
        case 'cet_status':
          data = await httpClient.get('/api/hw/cet_status');
          break;
        case 'avx512_state':
          data = await httpClient.get('/api/hw/avx512_state');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
