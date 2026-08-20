import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerModuleRebaserTools(server: McpServer) {
  server.tool(
    'x64dbg_module_rebaser',
    'Calculate and test PE module base shifts, check virtual address space collision risks, recompute export/import RVAs, and validate relocated pointers.',
    {
      action: z.enum(['simulate_rebase', 'check_address_conflicts', 'calculate_delta_map']).describe('Rebaser action'),
      module: z.string().optional().describe('Target module name'),
      target_base: z.string().describe('Proposed target base address (e.g. 0x00007FF700000000)'),
    },
    async ({ action, module, target_base }) => {
      let data: unknown;
      switch (action) {
        case 'simulate_rebase':
          data = await httpClient.post('/api/rebaser/simulate', { module, target_base });
          break;
        case 'check_address_conflicts':
          data = await httpClient.post('/api/rebaser/conflicts', { module, target_base });
          break;
        case 'calculate_delta_map':
          data = await httpClient.post('/api/rebaser/delta_map', { module, target_base });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
