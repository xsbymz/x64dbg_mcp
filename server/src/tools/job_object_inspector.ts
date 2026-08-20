import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerJobObjectInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_job_object_inspector',
    'Query Windows Job Objects associated with the target process: inspect process limits, memory caps, active process count, CPU rate limits, and security restrictions.',
    {
      action: z.enum(['query_process_job', 'get_job_limits', 'list_job_processes']).describe('Job Object action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'query_process_job':
          data = await httpClient.get('/api/job/info');
          break;
        case 'get_job_limits':
          data = await httpClient.get('/api/job/limits');
          break;
        case 'list_job_processes':
          data = await httpClient.get('/api/job/processes');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
