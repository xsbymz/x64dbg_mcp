import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHookScannerTools(server: McpServer) {
  server.tool(
    'x64dbg_hook_scanner',
    'Scan loaded system modules (ntdll, kernel32, user32, ws2_32) for user-mode inline hooks, EAT/IAT hooks, and compare memory instructions against clean on-disk PE bytes.',
    {
      action: z.enum(['scan_all', 'scan_module', 'list_modified_prologues', 'verify_export_table']).describe('Hook scanning operation'),
      module: z.string().optional().describe('Target module name (e.g. ntdll.dll, kernel32.dll)'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'scan_all':
          data = await httpClient.get('/api/hooks/scan_all');
          break;
        case 'scan_module':
          data = await httpClient.post('/api/hooks/scan_module', { module });
          break;
        case 'list_modified_prologues':
          data = await httpClient.post('/api/hooks/modified_prologues', { module });
          break;
        case 'verify_export_table':
          data = await httpClient.post('/api/hooks/verify_exports', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
