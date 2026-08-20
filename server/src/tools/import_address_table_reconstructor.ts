import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerImportAddressTableReconstructorTools(server: McpServer) {
  server.tool(
    'x64dbg_import_address_table_reconstructor',
    'Reconstruct destroyed or obfuscated Import Address Tables (IAT) by matching raw target pointers against loaded module export address spaces.',
    {
      action: z.enum(['reconstruct_iat_table', 'scan_pointer_ranges', 'export_rebuilt_iat']).describe('IAT reconstructor action'),
      iat_start_address: z.string().optional().describe('Virtual address of candidate IAT start'),
      iat_size: z.number().optional().describe('Estimated size in bytes of candidate IAT table'),
    },
    async ({ action, iat_start_address, iat_size }) => {
      let data: unknown;
      switch (action) {
        case 'reconstruct_iat_table':
          data = await httpClient.post('/api/iat_reconstruct/reconstruct', { iat_start_address, iat_size });
          break;
        case 'scan_pointer_ranges':
          data = await httpClient.post('/api/iat_reconstruct/scan_range', { iat_start_address, iat_size });
          break;
        case 'export_rebuilt_iat':
          data = await httpClient.post('/api/iat_reconstruct/export', { iat_start_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
