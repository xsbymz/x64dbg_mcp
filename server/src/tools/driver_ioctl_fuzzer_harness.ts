import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDriverIoctlFuzzerHarnessTools(server: McpServer) {
  server.tool(
    'x64dbg_driver_ioctl_fuzzer_harness',
    'Generate, validate, and fuzz IOCTL request packets (DeviceIoControl, METHOD_BUFFERED, METHOD_IN_DIRECT, METHOD_NEITHER) for driver auditing.',
    {
      action: z.enum(['generate_ioctl_packet', 'decode_ioctl_code', 'simulate_ioctl_dispatch']).describe('IOCTL harness action'),
      ioctl_code: z.number().optional().describe('32-bit IOCTL control code (e.g. 0x222000)'),
      device_name: z.string().optional().describe('Device name (e.g. \\\\.\\VulnerableDriver)'),
      input_size: z.number().optional().describe('Size in bytes of input buffer'),
    },
    async ({ action, ioctl_code, device_name, input_size }) => {
      let data: unknown;
      switch (action) {
        case 'generate_ioctl_packet':
          data = await httpClient.post('/api/ioctl_fuzzer/generate', { ioctl_code, input_size });
          break;
        case 'decode_ioctl_code':
          data = await httpClient.post('/api/ioctl_fuzzer/decode', { ioctl_code });
          break;
        case 'simulate_ioctl_dispatch':
          data = await httpClient.post('/api/ioctl_fuzzer/dispatch', { ioctl_code, device_name, input_size });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
