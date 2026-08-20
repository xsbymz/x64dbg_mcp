import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWindowsHookChainAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_windows_hook_chain_auditor',
    'Audit SetWindowsHookEx global and local hook chains (WH_KEYBOARD_LL, WH_MOUSE_LL, WH_CBT, WH_GETMESSAGE) in the current desktop session.',
    {
      action: z.enum(['list_installed_hooks', 'detect_keyloggers', 'get_hook_module_details']).describe('Windows hook action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'list_installed_hooks':
          data = await httpClient.get('/api/win_hooks/list');
          break;
        case 'detect_keyloggers':
          data = await httpClient.get('/api/win_hooks/keyloggers');
          break;
        case 'get_hook_module_details':
          data = await httpClient.get('/api/win_hooks/modules');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
