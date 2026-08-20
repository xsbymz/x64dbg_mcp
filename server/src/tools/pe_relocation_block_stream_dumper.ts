import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeRelocationBlockStreamDumperTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_relocation_block_stream_dumper',
    'Dump raw .reloc type-offset blocks (IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW) across all pages of a module.',
    {
      action: z.enum(['dump_all_blocks', 'get_page_relocs', 'count_reloc_types']).describe('Relocation dump action'),
      module_name: z.string().optional().describe('Module name (defaults to primary module)'),
      page_rva: z.string().optional().describe('Filter relocations for specific Page RVA'),
    },
    async ({ action, module_name, page_rva }) => {
      let data: unknown;
      switch (action) {
        case 'dump_all_blocks':
          data = await httpClient.post('/api/reloc_stream/all', { module_name });
          break;
        case 'get_page_relocs':
          data = await httpClient.post('/api/reloc_stream/page', { module_name, page_rva });
          break;
        case 'count_reloc_types':
          data = await httpClient.post('/api/reloc_stream/types', { module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
