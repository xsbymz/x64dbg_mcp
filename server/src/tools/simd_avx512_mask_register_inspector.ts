import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSimdAvx512MaskRegisterInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_simd_avx512_mask_register_inspector',
    'Inspect and format AVX-512 opmask registers (k0 through k7), bitmask predicates, and vector compression modes.',
    {
      action: z.enum(['get_mask_registers', 'format_as_bitmask', 'explain_mask_predicate']).describe('AVX-512 mask action'),
      mask_index: z.number().min(0).max(7).optional().describe('Opmask register index (0-7 for k0-k7)'),
    },
    async ({ action, mask_index }) => {
      let data: unknown;
      switch (action) {
        case 'get_mask_registers':
          data = await httpClient.get('/api/avx_mask/all');
          break;
        case 'format_as_bitmask':
          data = await httpClient.post('/api/avx_mask/bitmask', { mask_index });
          break;
        case 'explain_mask_predicate':
          data = await httpClient.post('/api/avx_mask/predicate', { mask_index });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
