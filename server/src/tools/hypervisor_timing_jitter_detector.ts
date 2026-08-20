import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHypervisorTimingJitterDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_hypervisor_timing_jitter_detector',
    'Detect hypervisor execution artifacts and VM exit overhead by analyzing fine-grained RDTSC execution jitter distributions.',
    {
      action: z.enum(['measure_rdtsc_jitter', 'get_jitter_histogram', 'detect_vmexit_spikes']).describe('Jitter detection action'),
      iterations: z.number().default(1000).describe('Number of RDTSC sample pairs to collect'),
    },
    async ({ action, iterations }) => {
      let data: unknown;
      switch (action) {
        case 'measure_rdtsc_jitter':
          data = await httpClient.post('/api/rdtsc_jitter/measure', { iterations });
          break;
        case 'get_jitter_histogram':
          data = await httpClient.get('/api/rdtsc_jitter/histogram');
          break;
        case 'detect_vmexit_spikes':
          data = await httpClient.get('/api/rdtsc_jitter/spikes');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
