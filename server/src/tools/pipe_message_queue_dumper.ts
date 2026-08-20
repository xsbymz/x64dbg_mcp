import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPipeMessageQueueDumperTools(server: McpServer) {
  server.tool(
    'x64dbg_pipe_message_queue_dumper',
    'Dump pending message buffers, read/write transaction queues, and client instance counts from active Win32 Named Pipes.',
    {
      action: z.enum(['dump_pipe_buffers', 'get_pipe_instances', 'list_pending_transactions']).describe('Pipe dumper action'),
      pipe_name: z.string().optional().describe('Pipe name (e.g. \\\\.\\pipe\\mypipe)'),
    },
    async ({ action, pipe_name }) => {
      let data: unknown;
      switch (action) {
        case 'dump_pipe_buffers':
          data = await httpClient.post('/api/pipe_dump/buffers', { pipe_name });
          break;
        case 'get_pipe_instances':
          data = await httpClient.post('/api/pipe_dump/instances', { pipe_name });
          break;
        case 'list_pending_transactions':
          data = await httpClient.post('/api/pipe_dump/transactions', { pipe_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
