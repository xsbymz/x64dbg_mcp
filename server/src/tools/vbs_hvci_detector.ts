import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerVbsHvciDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_vbs_hvci_detector',
    'Virtualization-Based Security (VBS), Hypervisor-Protected Code Integrity (HVCI), Credential Guard, and Isolated User Mode (IUM) trustlet state inspector.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('get_status')
        }),
        z.object({
          action: z.literal('inspect_isolated_user_mode')
        }),
        z.object({
          action: z.literal('check_code_integrity')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'get_status':
            data = await httpClient.post('/api/vbs_hvci/status', {});
            break;
          case 'inspect_isolated_user_mode':
            data = await httpClient.post('/api/vbs_hvci/isolated_user_mode', {});
            break;
          case 'check_code_integrity':
            data = await httpClient.post('/api/vbs_hvci/code_integrity', {});
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
