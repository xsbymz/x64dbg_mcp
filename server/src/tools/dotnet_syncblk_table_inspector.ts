import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDotnetSyncblkTableInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_dotnet_syncblk_table_inspector',
    'Inspect .NET CLR SyncBlockTable entries for locked object monitors, thin locks, COM IPromise tear-offs, and hash codes.',
    {
      action: z.enum(['list_active_syncblocks', 'inspect_object_syncblock', 'get_syncblk_lock_owner']).describe('SyncBlock action'),
      object_ptr: z.string().optional().describe('Virtual address of managed object pointer'),
    },
    async ({ action, object_ptr }) => {
      let data: unknown;
      switch (action) {
        case 'list_active_syncblocks':
          data = await httpClient.get('/api/clr_syncblk/list');
          break;
        case 'inspect_object_syncblock':
          data = await httpClient.post('/api/clr_syncblk/inspect', { object_ptr });
          break;
        case 'get_syncblk_lock_owner':
          data = await httpClient.post('/api/clr_syncblk/owner', { object_ptr });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
