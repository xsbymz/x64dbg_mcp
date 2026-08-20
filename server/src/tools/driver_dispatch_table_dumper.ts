import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDriverDispatchTableDumperTools(server: McpServer) {
  server.tool(
    'x64dbg_driver_dispatch_table_dumper',
    'Dump MajorFunction IRP dispatch tables (IRP_MJ_CREATE, IRP_MJ_READ, IRP_MJ_WRITE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_CLEANUP) from loaded kernel drivers.',
    {
      action: z.enum(['dump_dispatch_table', 'scan_hooked_dispatch_routines', 'list_driver_objects']).describe('Driver dispatch action'),
      driver_name: z.string().optional().describe('Driver name (e.g. \\Driver\\Disk or \\Driver\\Null)'),
    },
    async ({ action, driver_name }) => {
      let data: unknown;
      switch (action) {
        case 'dump_dispatch_table':
          data = await httpClient.post('/api/driver_dispatch/dump', { driver_name });
          break;
        case 'scan_hooked_dispatch_routines':
          data = await httpClient.post('/api/driver_dispatch/hooks', { driver_name });
          break;
        case 'list_driver_objects':
          data = await httpClient.get('/api/driver_dispatch/list');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
