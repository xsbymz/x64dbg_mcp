import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerEventTracingForWindowsTools(server: McpServer) {
  server.tool(
    'x64dbg_event_tracing_for_windows',
    'Inspect Event Tracing for Windows (ETW) sessions, enumerate registered ETW providers (e.g. Microsoft-Windows-Threat-Intelligence), and audit ETW registration handles (EtwEventRegister).',
    {
      action: z.enum(['list_registered_providers', 'list_active_sessions', 'inspect_provider_guids']).describe('ETW inspection action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'list_registered_providers':
          data = await httpClient.get('/api/etw_trace/providers');
          break;
        case 'list_active_sessions':
          data = await httpClient.get('/api/etw_trace/sessions');
          break;
        case 'inspect_provider_guids':
          data = await httpClient.get('/api/etw_trace/guids');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
