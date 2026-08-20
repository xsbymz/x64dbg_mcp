import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeExportOrdinalNameMapperTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_export_ordinal_name_mapper',
    'Map non-exported numeric ordinal exports back to known symbol databases, PDB symbols, and ordinal lookup tables.',
    {
      action: z.enum(['map_ordinal_to_name', 'list_ordinal_exports', 'batch_resolve_ordinals']).describe('Ordinal mapper action'),
      module_name: z.string().describe('Module name (e.g. mfc140.dll, ordinals.dll)'),
      ordinal: z.number().optional().describe('Numeric ordinal value to map'),
    },
    async ({ action, module_name, ordinal }) => {
      let data: unknown;
      switch (action) {
        case 'map_ordinal_to_name':
          data = await httpClient.post('/api/ordinal_map/resolve', { module_name, ordinal });
          break;
        case 'list_ordinal_exports':
          data = await httpClient.post('/api/ordinal_map/list', { module_name });
          break;
        case 'batch_resolve_ordinals':
          data = await httpClient.post('/api/ordinal_map/batch', { module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
