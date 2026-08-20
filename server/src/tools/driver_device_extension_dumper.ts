import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDriverDeviceExtensionDumperTools(server: McpServer) {
  server.tool(
    'x64dbg_driver_device_extension_dumper',
    'Dump kernel driver DEVICE_OBJECT->DeviceExtension memory blocks and attached device stacks for targeted device objects.',
    {
      action: z.enum(['dump_device_extension', 'get_attached_device_stack', 'list_device_objects']).describe('Device extension action'),
      device_ptr: z.string().describe('Virtual address of kernel DEVICE_OBJECT'),
    },
    async ({ action, device_ptr }) => {
      let data: unknown;
      switch (action) {
        case 'dump_device_extension':
          data = await httpClient.post('/api/device_ext/dump', { device_ptr });
          break;
        case 'get_attached_device_stack':
          data = await httpClient.post('/api/device_ext/stack', { device_ptr });
          break;
        case 'list_device_objects':
          data = await httpClient.post('/api/device_ext/list', { device_ptr });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
