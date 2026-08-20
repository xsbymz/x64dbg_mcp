import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerNtStatusCodeResolverTools(server: McpServer) {
  server.tool(
    'x64dbg_nt_status_code_resolver',
    'Resolve NTSTATUS codes, Win32 error codes, and HRESULTs (0xC0000005 -> STATUS_ACCESS_VIOLATION, 0x80070005 -> E_ACCESSDENIED) to human-readable names and descriptions.',
    {
      action: z.enum(['resolve_ntstatus', 'resolve_win32_error', 'resolve_hresult']).describe('Status resolver action'),
      code: z.string().describe('Status code hex string (e.g. 0xC0000005) or decimal number'),
    },
    async ({ action, code }) => {
      let data: unknown;
      switch (action) {
        case 'resolve_ntstatus':
          data = await httpClient.post('/api/status_resolver/ntstatus', { code });
          break;
        case 'resolve_win32_error':
          data = await httpClient.post('/api/status_resolver/win32', { code });
          break;
        case 'resolve_hresult':
          data = await httpClient.post('/api/status_resolver/hresult', { code });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
