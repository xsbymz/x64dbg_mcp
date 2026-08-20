import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDynamicBranchPredictorSimulatorTools(server: McpServer) {
  server.tool(
    'x64dbg_dynamic_branch_predictor_simulator',
    'Simulate hardware two-level adaptive branch predictor states (Branch History Table BHT, Pattern History Table PHT) on traced conditional branches to predict misprediction penalties.',
    {
      action: z.enum(['simulate_branch_trace', 'get_misprediction_rate', 'get_bht_state']).describe('Branch sim action'),
      branch_address: z.string().optional().describe('Branch instruction address'),
    },
    async ({ action, branch_address }) => {
      let data: unknown;
      switch (action) {
        case 'simulate_branch_trace':
          data = await httpClient.post('/api/branch_sim/trace', { branch_address });
          break;
        case 'get_misprediction_rate':
          data = await httpClient.get('/api/branch_sim/misprediction_rate');
          break;
        case 'get_bht_state':
          data = await httpClient.get('/api/branch_sim/bht_state');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
