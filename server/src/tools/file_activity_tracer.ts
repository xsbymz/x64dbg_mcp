import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFileActivityTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_file_activity_tracer',
    'Log and inspect filesystem operations executed by debuggee: track CreateFile, ReadFile, WriteFile, DeleteFile, SetFileInformation, and file path accesses.',
    {
      action: z.enum(['list_file_operations', 'list_open_files', 'get_written_buffers', 'clear_log']).describe('File activity action'),
      path_filter: z.string().optional().describe('Optional file path filter string'),
    },
    async ({ action, path_filter }) => {
      let data: unknown;
      switch (action) {
        case 'list_file_operations':
          data = await httpClient.post('/api/fs/operations', { path_filter });
          break;
        case 'list_open_files':
          data = await httpClient.get('/api/fs/open_files');
          break;
        case 'get_written_buffers':
          data = await httpClient.post('/api/fs/written_buffers', { path_filter });
          break;
        case 'clear_log':
          data = await httpClient.post('/api/fs/clear_log', {});
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
