import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerInstructionCycleProfilerTools(server: McpServer) {
  server.tool(
    'x64dbg_instruction_cycle_profiler',
    'Measure CPU clock cycle consumption (RDTSC/RDTSCP deltas) per basic block or instruction range to profile execution bottlenecks or detect timing traps.',
    {
      action: z.enum(['profile_instruction_range', 'measure_basic_block_cycles', 'detect_timing_anomalies']).describe('Cycle profiler action'),
      start_address: z.string().optional().describe('Virtual start address to begin cycle profiling'),
      end_address: z.string().optional().describe('Virtual end address to stop cycle profiling'),
    },
    async ({ action, start_address, end_address }) => {
      let data: unknown;
      switch (action) {
        case 'profile_instruction_range':
          data = await httpClient.post('/api/cycle_profiler/range', { start_address, end_address });
          break;
        case 'measure_basic_block_cycles':
          data = await httpClient.post('/api/cycle_profiler/basic_block', { start_address });
          break;
        case 'detect_timing_anomalies':
          data = await httpClient.get('/api/cycle_profiler/anomalies');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
