import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerEtwEventInjectorTools(server: McpServer) {
  server.tool(
    'x64dbg_etw_event_injector',
    'Simulate ETW event dispatches (EventWrite, EventWriteTransfer) to test target application security telemetry filters and event log receivers.',
    {
      action: z.enum(['inject_custom_event', 'simulate_threat_intel_event', 'list_registered_handles']).describe('ETW injector action'),
      provider_guid: z.string().optional().describe('Provider GUID string'),
      event_id: z.number().optional().describe('Event descriptor ID'),
      payload_hex: z.string().optional().describe('Hexadecimal event payload data'),
    },
    async ({ action, provider_guid, event_id, payload_hex }) => {
      let data: unknown;
      switch (action) {
        case 'inject_custom_event':
          data = await httpClient.post('/api/etw_inject/custom', { provider_guid, event_id, payload_hex });
          break;
        case 'simulate_threat_intel_event':
          data = await httpClient.post('/api/etw_inject/threat_intel', { event_id });
          break;
        case 'list_registered_handles':
          data = await httpClient.get('/api/etw_inject/handles');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
