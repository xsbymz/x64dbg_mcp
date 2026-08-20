import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDynamicCodeCaveAllocatorTools(server: McpServer) {
  server.tool(
    'x64dbg_dynamic_code_cave_allocator',
    'Allocate and prepare executable memory code caves near target modules (within 2GB branch limit for RIP-relative 5-byte JMP/CALL instructions).',
    {
      action: z.enum(['allocate_near_module', 'list_allocated_caves', 'free_code_cave']).describe('Code cave action'),
      module_name: z.string().optional().describe('Target module name (e.g. ntdll.dll or target.exe)'),
      size: z.number().optional().describe('Cave size in bytes (default 4096)'),
      cave_address: z.string().optional().describe('Address of the cave to free'),
    },
    async ({ action, module_name, size, cave_address }) => {
      let data: unknown;
      switch (action) {
        case 'allocate_near_module':
          data = await httpClient.post('/api/code_cave/alloc', { module_name, size });
          break;
        case 'list_allocated_caves':
          data = await httpClient.get('/api/code_cave/list');
          break;
        case 'free_code_cave':
          data = await httpClient.post('/api/code_cave/free', { cave_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
