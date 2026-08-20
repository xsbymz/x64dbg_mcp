import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerUnrealUnityIntrospectorTools(server: McpServer) {
  server.tool(
    'x64dbg_unreal_unity_introspector',
    'Unreal Engine (GUObjectArray, GNames, GWorld) and Unity IL2CPP runtime metadata and class hierarchy introspector.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('unreal_objects')
        }),
        z.object({
          action: z.literal('unity_il2cpp')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'unreal_objects':
            data = await httpClient.post('/api/game_engine/unreal_objects', {});
            break;
          case 'unity_il2cpp':
            data = await httpClient.post('/api/game_engine/unity_il2cpp', {});
            break;
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
