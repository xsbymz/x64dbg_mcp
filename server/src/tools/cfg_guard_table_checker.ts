import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCfgGuardTableCheckerTools(server: McpServer) {
  server.tool(
    'x64dbg_cfg_guard_table_checker',
    'Verify Control Flow Guard (CFG) valid call target bitmap and check whether an indirect call target address is registered in the module GuardCFFunctionTable.',
    {
      action: z.enum(['check_target_address', 'dump_guard_table', 'get_guard_bitmap_state']).describe('CFG guard table action'),
      module: z.string().optional().describe('Target module name'),
      address: z.string().optional().describe('Target virtual address to check for CFG validity'),
    },
    async ({ action, module, address }) => {
      let data: unknown;
      switch (action) {
        case 'check_target_address':
          data = await httpClient.post('/api/cfg_guard/check_address', { module, address });
          break;
        case 'dump_guard_table':
          data = await httpClient.post('/api/cfg_guard/dump_table', { module });
          break;
        case 'get_guard_bitmap_state':
          data = await httpClient.post('/api/cfg_guard/bitmap_state', { address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
