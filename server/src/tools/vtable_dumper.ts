import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerVtableDumperTools(server: McpServer) {
  server.tool(
    'x64dbg_vtable_dumper',
    'Exhaustively dump C++ virtual method tables (VTables) from module data sections (.rdata), resolve method names via PDB/RTTI, and generate C++ polymorphic interface headers.',
    {
      action: z.enum(['dump_all_vtables', 'dump_vtable_at', 'export_cpp_interface', 'find_orphaned_vtables']).describe('VTable action'),
      module: z.string().optional().describe('Target module name'),
      address: z.string().optional().describe('Specific VTable memory address'),
      class_name: z.string().optional().default('CustomInterface').describe('Class name for C++ interface export'),
    },
    async ({ action, module, address, class_name }) => {
      let data: unknown;
      switch (action) {
        case 'dump_all_vtables':
          data = await httpClient.post('/api/vtable_dump/all', { module });
          break;
        case 'dump_vtable_at':
          data = await httpClient.post('/api/vtable_dump/at', { address });
          break;
        case 'export_cpp_interface':
          data = await httpClient.post('/api/vtable_dump/export_interface', { address, class_name });
          break;
        case 'find_orphaned_vtables':
          data = await httpClient.post('/api/vtable_dump/orphaned', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
