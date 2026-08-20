import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRelocationFixerTools(server: McpServer) {
  server.tool(
    'x64dbg_relocation_fixer',
    'Verify and apply PE base relocations (.reloc block directory): recalculate relocated pointers, fix image base shifts, and check relocation validity.',
    {
      action: z.enum(['parse_relocs', 'apply_relocs', 'verify_relocs', 'rebase_image']).describe('Relocation operation'),
      module: z.string().optional().describe('Target module name'),
      new_base: z.string().optional().describe('New image base address for rebase calculation'),
    },
    async ({ action, module, new_base }) => {
      let data: unknown;
      switch (action) {
        case 'parse_relocs':
          data = await httpClient.post('/api/reloc/parse', { module });
          break;
        case 'apply_relocs':
          data = await httpClient.post('/api/reloc/apply', { module, new_base });
          break;
        case 'verify_relocs':
          data = await httpClient.post('/api/reloc/verify', { module });
          break;
        case 'rebase_image':
          data = await httpClient.post('/api/reloc/rebase', { module, new_base });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
