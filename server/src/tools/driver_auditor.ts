import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDriverAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_driver_auditor',
    'Inspect loaded kernel drivers, query device object permissions, enumerate driver dispatch tables (IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL), and inspect system service security descriptors.',
    {
      action: z.enum(['list_drivers', 'inspect_device_objects', 'get_dispatch_routines', 'check_known_vulnerable_drivers']).describe('Driver audit action'),
      driver_name: z.string().optional().describe('Driver base name (e.g. RTCore64.sys, DBGHELP.sys)'),
    },
    async ({ action, driver_name }) => {
      let data: unknown;
      switch (action) {
        case 'list_drivers':
          data = await httpClient.get('/api/driver/list');
          break;
        case 'inspect_device_objects':
          data = await httpClient.post('/api/driver/device_objects', { driver_name });
          break;
        case 'get_dispatch_routines':
          data = await httpClient.post('/api/driver/dispatch_routines', { driver_name });
          break;
        case 'check_known_vulnerable_drivers':
          data = await httpClient.get('/api/driver/check_vulnerable');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
