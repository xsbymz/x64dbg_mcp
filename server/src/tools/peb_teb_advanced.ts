import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPebTebAdvancedTools(server: McpServer) {
  server.tool(
    'x64dbg_peb_teb_advanced',
    'Inspect advanced PEB and TEB internal fields: FastPebLock, GdiSharedHandleTable, FLS (Fiber Local Storage) slots, TlsExpansionSlots, and ActiveFrame chains.',
    {
      action: z.enum(['inspect_peb_locks', 'inspect_gdi_table', 'inspect_fls_slots', 'inspect_active_frames']).describe('PEB/TEB action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'inspect_peb_locks':
          data = await httpClient.get('/api/peb_teb_adv/locks');
          break;
        case 'inspect_gdi_table':
          data = await httpClient.get('/api/peb_teb_adv/gdi_table');
          break;
        case 'inspect_fls_slots':
          data = await httpClient.get('/api/peb_teb_adv/fls_slots');
          break;
        case 'inspect_active_frames':
          data = await httpClient.get('/api/peb_teb_adv/active_frames');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
