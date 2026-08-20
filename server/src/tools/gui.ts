import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerGuiTools(server: McpServer) {
  server.tool(
    'x64dbg_gui',
    'Inspect GUI windows, dialogs, buttons, controls, and window procedures (WndProc) in the debugged process. ' +
    'Enables direct identification of UI message handlers, button click routines, registration dialogs, and nag screens.',
    {
      action: z.enum(['windows']).describe('Action: windows (enumerate all top-level and child GUI windows/dialogs/controls with WndProc addresses)')
    },
    async ({ action }) => {
      try {
        const data = await httpClient.get('/api/gui/windows');
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
