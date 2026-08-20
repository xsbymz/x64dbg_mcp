import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerNamedPipeSecurityCheckerTools(server: McpServer) {
  server.tool(
    'x64dbg_named_pipe_security_checker',
    'Check security descriptors, access masks, client impersonation levels, and world-writable permissions on Win32 Named Pipes.',
    {
      action: z.enum(['check_pipe_security', 'list_dangerous_pipes', 'get_pipe_dacl']).describe('Pipe security action'),
      pipe_name: z.string().optional().describe('Named pipe name (e.g. \\\\.\\pipe\\testpipe)'),
    },
    async ({ action, pipe_name }) => {
      let data: unknown;
      switch (action) {
        case 'check_pipe_security':
          data = await httpClient.post('/api/pipe_sec_desc/check', { pipe_name });
          break;
        case 'list_dangerous_pipes':
          data = await httpClient.get('/api/pipe_sec_desc/dangerous');
          break;
        case 'get_pipe_dacl':
          data = await httpClient.post('/api/pipe_sec_desc/dacl', { pipe_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
