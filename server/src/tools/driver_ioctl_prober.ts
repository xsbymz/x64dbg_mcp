import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDriverIoctlProberTools(server: McpServer) {
  server.tool(
    'x64dbg_driver_ioctl_prober',
    'Driver IOCTL dynamic dispatch monitor, NtDeviceIoControlFile parameter recorder, and IOCTL code structure analyzer.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('record_dispatches')
        }),
        z.object({
          action: z.literal('probe_ioctl_code'),
          ioctl_code: z.string().optional()
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'record_dispatches':
            data = await httpClient.post('/api/driver_ioctl/record_dispatches', {});
            break;
          case 'probe_ioctl_code':
            data = await httpClient.post('/api/driver_ioctl/probe_ioctl_code', {
              ioctl_code: action.ioctl_code
            });
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
