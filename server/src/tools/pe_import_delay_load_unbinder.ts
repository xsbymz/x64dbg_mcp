import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeImportDelayLoadUnbinderTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_import_delay_load_unbinder',
    'Unbind or reset resolved delay-load modules back to uninitialized helper stubs (__pfnDliFailureHook2, delay IAT reset).',
    {
      action: z.enum(['unbind_module', 'list_bound_delay_imports', 'reset_delay_iat']).describe('Delay-load unbinder action'),
      dll_name: z.string().describe('Delay-load DLL name to unbind (e.g. user32.dll)'),
      module_name: z.string().optional().describe('Parent module containing the delay import'),
    },
    async ({ action, dll_name, module_name }) => {
      let data: unknown;
      switch (action) {
        case 'unbind_module':
          data = await httpClient.post('/api/delay_unbind/unbind', { dll_name, module_name });
          break;
        case 'list_bound_delay_imports':
          data = await httpClient.post('/api/delay_unbind/list', { module_name });
          break;
        case 'reset_delay_iat':
          data = await httpClient.post('/api/delay_unbind/reset', { dll_name, module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
