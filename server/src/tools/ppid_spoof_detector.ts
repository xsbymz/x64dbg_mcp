import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPpidSpoofDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_ppid_spoof_detector',
    'Parent Process ID (PPID) & Command Line Argument Spoofing Auditor. Identify spoofed parent processes, unmask hidden execution arguments, and validate process lineage.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('audit_ppid')
        }),
        z.object({
          action: z.literal('check_cmdline')
        }),
        z.object({
          action: z.literal('validate_lineage')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'audit_ppid':
            data = await httpClient.post('/api/ppid_spoof/audit', {});
            break;
          case 'check_cmdline':
            data = await httpClient.post('/api/ppid_spoof/cmdline_check', {});
            break;
          case 'validate_lineage':
            data = await httpClient.post('/api/ppid_spoof/tree_validate', {});
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
