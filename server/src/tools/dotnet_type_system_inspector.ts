import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDotnetTypeSystemInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_dotnet_type_system_inspector',
    'Resolve .NET internal type system structures (MethodTable, EEClass, FieldDesc, MethodDesc, and instance field offsets) from memory addresses.',
    {
      action: z.enum(['inspect_method_table', 'inspect_eeclass', 'list_instance_fields', 'dump_vtable_slots']).describe('Type system action'),
      method_table_address: z.string().describe('Address of the MethodTable pointer in target memory'),
    },
    async ({ action, method_table_address }) => {
      let data: unknown;
      switch (action) {
        case 'inspect_method_table':
          data = await httpClient.post('/api/dotnet_type/method_table', { method_table_address });
          break;
        case 'inspect_eeclass':
          data = await httpClient.post('/api/dotnet_type/eeclass', { method_table_address });
          break;
        case 'list_instance_fields':
          data = await httpClient.post('/api/dotnet_type/fields', { method_table_address });
          break;
        case 'dump_vtable_slots':
          data = await httpClient.post('/api/dotnet_type/vtable_slots', { method_table_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
