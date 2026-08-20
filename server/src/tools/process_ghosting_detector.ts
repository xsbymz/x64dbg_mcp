import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerProcessGhostingDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_process_ghosting_detector',
    'Process Ghosting, Herpaderping, Doppelgänging & Transacted Section Detector. Detect delete-pending image sections, disk-memory binary discrepancies, and NTFS transaction abuse.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('scan_ghosting')
        }),
        z.object({
          action: z.literal('check_herpaderping')
        }),
        z.object({
          action: z.literal('inspect_transactions')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'scan_ghosting':
            data = await httpClient.post('/api/ghosting/scan', {});
            break;
          case 'check_herpaderping':
            data = await httpClient.post('/api/ghosting/herpaderping', {});
            break;
          case 'inspect_transactions':
            data = await httpClient.post('/api/ghosting/transactions', {});
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
