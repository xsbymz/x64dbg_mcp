import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerComInterfaceProxyStubWalkerTools(server: McpServer) {
  server.tool(
    'x64dbg_com_interface_proxy_stub_walker',
    'Map standard COM cross-process marshaling dispatch tables (IRpcProxyBuffer, IRpcStubBuffer, CInterfaceProxyHeader, CInterfaceStubHeader).',
    {
      action: z.enum(['list_proxy_stubs', 'inspect_proxy_header', 'inspect_stub_header']).describe('Proxy stub action'),
      iid: z.string().optional().describe('Interface IID GUID string'),
    },
    async ({ action, iid }) => {
      let data: unknown;
      switch (action) {
        case 'list_proxy_stubs':
          data = await httpClient.get('/api/proxy_stub/list');
          break;
        case 'inspect_proxy_header':
          data = await httpClient.post('/api/proxy_stub/proxy', { iid });
          break;
        case 'inspect_stub_header':
          data = await httpClient.post('/api/proxy_stub/stub', { iid });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
