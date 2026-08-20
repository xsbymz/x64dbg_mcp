import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerNamedPipeImpersonationCheckerTools(server: McpServer) {
  server.tool(
    'x64dbg_named_pipe_impersonation_checker',
    'Audit ImpersonateNamedPipeClient API calls, identifying token privilege escalation pathways and client impersonation levels.',
    {
      action: z.enum(['audit_pipe_impersonation', 'inspect_pipe_security_descriptor', 'check_client_token']).describe('Pipe impersonation action'),
      pipe_handle: z.number().optional().describe('Open Named Pipe handle to audit'),
    },
    async ({ action, pipe_handle }) => {
      let data: unknown;
      switch (action) {
        case 'audit_pipe_impersonation':
          data = await httpClient.get('/api/pipe_sec/audit');
          break;
        case 'inspect_pipe_security_descriptor':
          data = await httpClient.post('/api/pipe_sec/security_descriptor', { pipe_handle });
          break;
        case 'check_client_token':
          data = await httpClient.post('/api/pipe_sec/client_token', { pipe_handle });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
