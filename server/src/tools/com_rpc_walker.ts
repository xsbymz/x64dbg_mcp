import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerComRpcWalkerTools(server: McpServer) {
  server.tool(
    'x64dbg_com_rpc_walker',
    'Walk and resolve COM interface VTables (IUnknown, IDispatch), map GUIDs/IIDs to human-readable names, and inspect active RPC endpoints in memory.',
    {
      action: z.enum(['inspect_interface', 'resolve_guid', 'list_active_interfaces']).describe('COM/RPC inspection action'),
      address: z.string().optional().describe('Pointer to COM object interface or VTable'),
      guid: z.string().optional().describe('GUID / IID string to resolve (e.g. {00000000-0000-0000-C000-000000000046})'),
    },
    async ({ action, address, guid }) => {
      let data: unknown;
      switch (action) {
        case 'inspect_interface':
          data = await httpClient.post('/api/com/inspect_interface', { address });
          break;
        case 'resolve_guid':
          data = await httpClient.post('/api/com/resolve_guid', { guid });
          break;
        case 'list_active_interfaces':
          data = await httpClient.get('/api/com/list_active_interfaces');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
