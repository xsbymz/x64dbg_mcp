import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRpcAlpcInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_rpc_alpc_inspector',
    'Inspect Windows Advanced Local Procedure Call (ALPC) port handles, message queues, connected clients/servers, and RPC communication endpoints.',
    {
      action: z.enum(['list_alpc_ports', 'inspect_port_messages', 'query_rpc_endpoints']).describe('ALPC/RPC action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'list_alpc_ports':
          data = await httpClient.get('/api/alpc/ports');
          break;
        case 'inspect_port_messages':
          data = await httpClient.get('/api/alpc/messages');
          break;
        case 'query_rpc_endpoints':
          data = await httpClient.get('/api/alpc/rpc_endpoints');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
