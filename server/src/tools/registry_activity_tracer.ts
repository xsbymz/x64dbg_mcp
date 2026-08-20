import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRegistryActivityTracerTools(server: McpServer) {
  server.tool(
    'x64dbg_registry_activity_tracer',
    'Track dynamic Windows registry activity: log RegOpenKeyEx, RegCreateKeyEx, RegSetValueEx, RegQueryValueEx, and detect persistence keys tampering (Run/RunOnce).',
    {
      action: z.enum(['list_registry_operations', 'list_modified_keys', 'check_persistence_keys', 'clear_log']).describe('Registry action'),
      key_filter: z.string().optional().describe('Registry path substring filter'),
    },
    async ({ action, key_filter }) => {
      let data: unknown;
      switch (action) {
        case 'list_registry_operations':
          data = await httpClient.post('/api/reg/operations', { key_filter });
          break;
        case 'list_modified_keys':
          data = await httpClient.post('/api/reg/modified_keys', { key_filter });
          break;
        case 'check_persistence_keys':
          data = await httpClient.get('/api/reg/persistence_check');
          break;
        case 'clear_log':
          data = await httpClient.post('/api/reg/clear_log', {});
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
