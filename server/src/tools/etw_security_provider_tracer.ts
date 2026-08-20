import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerEtwSecurityProviderTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_etw_security_provider_tracer',
    'Trace security-critical ETW event providers (Microsoft-Windows-Security-Mitigations, Microsoft-Windows-Kernel-Audit-API-Calls, Microsoft-Windows-Threat-Intelligence).',
    {
      action: z.enum(['list_security_providers', 'capture_security_events', 'get_provider_guid']).describe('ETW security tracer action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'list_security_providers':
          data = await httpClient.get('/api/etw_sec/providers');
          break;
        case 'capture_security_events':
          data = await httpClient.get('/api/etw_sec/capture');
          break;
        case 'get_provider_guid':
          data = await httpClient.get('/api/etw_sec/guids');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
