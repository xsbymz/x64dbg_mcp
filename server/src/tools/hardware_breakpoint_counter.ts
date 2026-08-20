import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHardwareBreakpointCounterTools(server: McpServer) {
  server.tool(
    'x64dbg_hardware_breakpoint_counter',
    'Measure exact hardware debug register (DR0-DR3) hit counts and frequency deltas without pausing target execution (stealth hit profiling).',
    {
      action: z.enum(['get_hit_counters', 'reset_hit_counters', 'get_hit_rate_per_sec']).describe('HW BP counter action'),
      slot: z.number().optional().describe('Hardware debug slot index (0 to 3)'),
    },
    async ({ action, slot }) => {
      let data: unknown;
      switch (action) {
        case 'get_hit_counters':
          data = await httpClient.get('/api/hw_counter/counters');
          break;
        case 'reset_hit_counters':
          data = await httpClient.post('/api/hw_counter/reset', { slot });
          break;
        case 'get_hit_rate_per_sec':
          data = await httpClient.get('/api/hw_counter/rates');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
