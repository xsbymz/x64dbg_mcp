import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerComClassFactoryInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_com_class_factory_inspector',
    'Instantiate and query COM Class Factories (IClassFactory::CreateInstance, IClassFactory2::CreateInstanceLic) and inspect server registrations.',
    {
      action: z.enum(['inspect_class_factory', 'query_clsid_registration', 'list_supported_interfaces']).describe('Class factory action'),
      clsid: z.string().optional().describe('CLSID GUID string (e.g. {0002DF01-0000-0000-C000-000000000046})'),
    },
    async ({ action, clsid }) => {
      let data: unknown;
      switch (action) {
        case 'inspect_class_factory':
          data = await httpClient.post('/api/class_factory/inspect', { clsid });
          break;
        case 'query_clsid_registration':
          data = await httpClient.post('/api/class_factory/query', { clsid });
          break;
        case 'list_supported_interfaces':
          data = await httpClient.post('/api/class_factory/interfaces', { clsid });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
