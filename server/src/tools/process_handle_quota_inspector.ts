import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerProcessHandleQuotaInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_process_handle_quota_inspector',
    'Query process object limits and memory quotas: PagedPoolQuota, NonPagedPoolQuota, PagefileQuota, and HandleLimit.',
    {
      action: z.enum(['get_process_quotas', 'get_handle_count', 'check_quota_exhaustion']).describe('Handle quota action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'get_process_quotas':
          data = await httpClient.get('/api/handle_quota/quotas');
          break;
        case 'get_handle_count':
          data = await httpClient.get('/api/handle_quota/count');
          break;
        case 'check_quota_exhaustion':
          data = await httpClient.get('/api/handle_quota/exhaustion');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
