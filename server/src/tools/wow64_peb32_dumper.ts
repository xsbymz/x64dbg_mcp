import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWow64Peb32DumperTools(server: McpServer) {
  server.tool(
    'x64dbg_wow64_peb32_dumper',
    'Dump 32-bit PEB32, RTL_USER_PROCESS_PARAMETERS32, and 32-bit Loaded Module list from 64-bit debug session.',
    {
      action: z.enum(['dump_peb32', 'get_process_parameters32', 'list_modules32']).describe('PEB32 action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'dump_peb32':
          data = await httpClient.get('/api/peb32_dump/peb');
          break;
        case 'get_process_parameters32':
          data = await httpClient.get('/api/peb32_dump/params');
          break;
        case 'list_modules32':
          data = await httpClient.get('/api/peb32_dump/modules');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
