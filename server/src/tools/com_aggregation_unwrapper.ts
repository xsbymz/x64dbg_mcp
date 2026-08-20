import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerComAggregationUnwrapperTools(server: McpServer) {
  server.tool(
    'x64dbg_com_aggregation_unwrapper',
    'Inspect COM object aggregation outer IUnknown vs inner IUnknown delegates, tear-off interfaces, and identity rules.',
    {
      action: z.enum(['inspect_aggregation', 'get_inner_unknown', 'verify_identity_rule']).describe('Aggregation action'),
      com_ptr: z.string().describe('Virtual address of COM object interface pointer'),
    },
    async ({ action, com_ptr }) => {
      let data: unknown;
      switch (action) {
        case 'inspect_aggregation':
          data = await httpClient.post('/api/com_aggr/inspect', { com_ptr });
          break;
        case 'get_inner_unknown':
          data = await httpClient.post('/api/com_aggr/inner', { com_ptr });
          break;
        case 'verify_identity_rule':
          data = await httpClient.post('/api/com_aggr/identity', { com_ptr });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
