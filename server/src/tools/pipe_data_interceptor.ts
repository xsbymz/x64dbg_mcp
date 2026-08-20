import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPipeDataInterceptorTools(server: McpServer) {
  server.tool(
    'x64dbg_pipe_data_interceptor',
    'Intercept and record Win32 Named Pipe read/write buffers (CreateNamedPipe, ReadFile, WriteFile, TransactNamedPipe) and decode protocol structures.',
    {
      action: z.enum(['list_intercepted_pipes', 'get_pipe_stream', 'clear_pipe_logs']).describe('Named Pipe action'),
      pipe_name: z.string().optional().describe('Filter by specific pipe name (e.g. \\\\.\\pipe\\mypipe)'),
    },
    async ({ action, pipe_name }) => {
      let data: unknown;
      switch (action) {
        case 'list_intercepted_pipes':
          data = await httpClient.get('/api/pipe_intercept/list');
          break;
        case 'get_pipe_stream':
          data = await httpClient.post('/api/pipe_intercept/stream', { pipe_name });
          break;
        case 'clear_pipe_logs':
          data = await httpClient.post('/api/pipe_intercept/clear', {});
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
