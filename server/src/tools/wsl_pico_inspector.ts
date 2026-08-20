import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWslPicoInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_wsl_pico_inspector',
    'Windows Subsystem for Linux (WSL) & Pico Process Interop Inspector. Detect Pico provider subsystems, inspect vsock IPC channels, and audit cross-subsystem syscall translation.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('detect_pico_subsystem')
        }),
        z.object({
          action: z.literal('inspect_channels')
        }),
        z.object({
          action: z.literal('map_syscall_matrix')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'detect_pico_subsystem':
            data = await httpClient.post('/api/wsl_pico/detect', {});
            break;
          case 'inspect_channels':
            data = await httpClient.post('/api/wsl_pico/channels', {});
            break;
          case 'map_syscall_matrix':
            data = await httpClient.post('/api/wsl_pico/syscall_matrix', {});
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
