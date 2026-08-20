import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerEntropyDeltaMonitorTools(server: McpServer) {
  server.tool(
    'x64dbg_entropy_delta_monitor',
    'Continuously monitor Shannon entropy shifts in executable pages during execution steps to detect in-memory decryption / unpacking loops.',
    {
      action: z.enum(['start_monitoring', 'stop_monitoring', 'get_entropy_deltas']).describe('Entropy delta action'),
      address: z.string().optional().describe('Base address of region to monitor'),
      size: z.number().optional().describe('Size of region to monitor in bytes'),
    },
    async ({ action, address, size }) => {
      let data: unknown;
      switch (action) {
        case 'start_monitoring':
          data = await httpClient.post('/api/entropy_delta/start', { address, size });
          break;
        case 'stop_monitoring':
          data = await httpClient.post('/api/entropy_delta/stop', {});
          break;
        case 'get_entropy_deltas':
          data = await httpClient.get('/api/entropy_delta/deltas');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
