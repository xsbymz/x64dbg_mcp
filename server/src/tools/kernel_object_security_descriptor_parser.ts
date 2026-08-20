import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerKernelObjectSecurityDescriptorParserTools(server: McpServer) {
  server.tool(
    'x64dbg_kernel_object_security_descriptor_parser',
    'Parse SECURITY_DESCRIPTOR structures (DACL, SACL, Owner SID, Group SID) on kernel objects from handle or memory address.',
    {
      action: z.enum(['parse_from_handle', 'parse_from_address', 'get_dacl_aces']).describe('Security descriptor action'),
      handle: z.number().optional().describe('Object handle value'),
      address: z.string().optional().describe('Memory address of SECURITY_DESCRIPTOR structure'),
    },
    async ({ action, handle, address }) => {
      let data: unknown;
      switch (action) {
        case 'parse_from_handle':
          data = await httpClient.post('/api/sec_desc/handle', { handle });
          break;
        case 'parse_from_address':
          data = await httpClient.post('/api/sec_desc/address', { address });
          break;
        case 'get_dacl_aces':
          data = await httpClient.post('/api/sec_desc/dacl', { handle, address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
