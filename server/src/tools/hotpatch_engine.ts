import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHotpatchEngineTools(server: McpServer) {
  server.tool(
    'x64dbg_hotpatch_engine',
    'Non-destructive live function hooking and hotpatching engine: install prologue trampolines, hook functions at runtime, inspect active hotpatches, and restore original bytes.',
    {
      action: z.enum(['install_hook', 'remove_hook', 'list_hotpatches', 'test_trampoline']).describe('Hotpatch action'),
      target_address: z.string().optional().describe('Target function address to hook'),
      detour_address: z.string().optional().describe('Detour/replacement function address'),
      patch_id: z.string().optional().describe('Identifier of active hotpatch to remove or test'),
    },
    async ({ action, target_address, detour_address, patch_id }) => {
      let data: unknown;
      switch (action) {
        case 'install_hook':
          data = await httpClient.post('/api/hotpatch/install', { target_address, detour_address });
          break;
        case 'remove_hook':
          data = await httpClient.post('/api/hotpatch/remove', { patch_id, target_address });
          break;
        case 'list_hotpatches':
          data = await httpClient.get('/api/hotpatch/list');
          break;
        case 'test_trampoline':
          data = await httpClient.post('/api/hotpatch/test', { patch_id });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
