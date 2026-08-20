import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDllHijackAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_dll_hijack_auditor',
    'Audit DLL search order, identify missing dynamic link libraries loaded via LoadLibrary/static imports, and assess DLL sideloading risks.',
    {
      action: z.enum(['audit_missing_dlls', 'get_search_order', 'check_known_dlls']).describe('DLL hijack audit action'),
      module: z.string().optional().describe('Target module name'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'audit_missing_dlls':
          data = await httpClient.post('/api/dll_hijack/missing', { module });
          break;
        case 'get_search_order':
          data = await httpClient.get('/api/dll_hijack/search_order');
          break;
        case 'check_known_dlls':
          data = await httpClient.get('/api/dll_hijack/known_dlls');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
