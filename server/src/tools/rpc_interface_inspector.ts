import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRpcInterfaceInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_rpc_interface_inspector',
    'RPC Interface UUID & Dispatch Table Security Auditor. Enumerate RPC interfaces, dump NDR dispatch tables, and audit RPC security callbacks.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('enum_interfaces')
        }),
        z.object({
          action: z.literal('dump_dispatch_table'),
          dispatch_table_address: z.string().describe('Dispatch table pointer (e.g. "0x403000")'),
          methods_count: z.number().optional().describe('Number of methods to dump')
        }),
        z.object({
          action: z.literal('audit_security_callbacks')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'enum_interfaces':
            data = await httpClient.post('/api/rpc_interface/enum', {});
            break;
          case 'dump_dispatch_table':
            data = await httpClient.post('/api/rpc_interface/dispatch_table', {
              dispatch_table_address: action.dispatch_table_address,
              methods_count: action.methods_count
            });
            break;
          case 'audit_security_callbacks':
            data = await httpClient.post('/api/rpc_interface/security_callback', {});
            break;
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
