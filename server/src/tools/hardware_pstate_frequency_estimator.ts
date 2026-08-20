import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHardwarePstateFrequencyEstimatorTools(server: McpServer) {
  server.tool(
    'x64dbg_hardware_pstate_frequency_estimator',
    'Estimate effective CPU core P-state, turbo frequencies, and timestamp counter frequency using RDTSC and APERF/MPERF ratios.',
    {
      action: z.enum(['estimate_frequency', 'get_tsc_calibration', 'detect_thermal_throttling']).describe('CPU frequency action'),
      sample_ms: z.number().default(100).describe('Measurement sample window in milliseconds'),
    },
    async ({ action, sample_ms }) => {
      let data: unknown;
      switch (action) {
        case 'estimate_frequency':
          data = await httpClient.post('/api/cpu_freq/estimate', { sample_ms });
          break;
        case 'get_tsc_calibration':
          data = await httpClient.get('/api/cpu_freq/tsc');
          break;
        case 'detect_thermal_throttling':
          data = await httpClient.get('/api/cpu_freq/throttling');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
