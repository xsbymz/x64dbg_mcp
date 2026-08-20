import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerIatCamouflagingDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_iat_camouflaging_detector',
    'Detect manual IAT resolving loops, dynamic API hash decoders (CRC32, ROR13, MurmurHash, Jenkins), and custom runtime export resolution.',
    {
      action: z.enum(['scan_resolving_loops', 'identify_hash_algorithms', 'trace_custom_iat']).describe('IAT camouflage action'),
      function_address: z.string().optional().describe('Virtual address of resolving function'),
    },
    async ({ action, function_address }) => {
      let data: unknown;
      switch (action) {
        case 'scan_resolving_loops':
          data = await httpClient.post('/api/iat_camo/scan', { function_address });
          break;
        case 'identify_hash_algorithms':
          data = await httpClient.post('/api/iat_camo/hash_types', { function_address });
          break;
        case 'trace_custom_iat':
          data = await httpClient.post('/api/iat_camo/trace', { function_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
