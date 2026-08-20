import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeComDescriptorParserTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_com_descriptor_parser',
    'Parse IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (IMAGE_COR20_HEADER, Major/Minor RuntimeVersion, Flags, StrongNameSignature, VTableFixups).',
    {
      action: z.enum(['parse_cor20_header', 'list_vtable_fixups', 'verify_strong_name']).describe('COM descriptor action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'parse_cor20_header':
          data = await httpClient.get('/api/pe_cor20/header');
          break;
        case 'list_vtable_fixups':
          data = await httpClient.get('/api/pe_cor20/vtable_fixups');
          break;
        case 'verify_strong_name':
          data = await httpClient.get('/api/pe_cor20/strong_name');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
