import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSimdVectorDifferTools(server: McpServer) {
  server.tool(
    'x64dbg_simd_vector_differ',
    'Compare and diff SIMD vector registers (XMM0-XMM15, YMM0-YMM15, ZMM0-ZMM31) across execution steps with byte, float32, float64, and int64 interpretations.',
    {
      action: z.enum(['snapshot_simd', 'diff_simd_vectors', 'get_vector_lanes']).describe('SIMD diff action'),
      register_name: z.string().optional().describe('Vector register name (e.g. XMM0, YMM1)'),
    },
    async ({ action, register_name }) => {
      let data: unknown;
      switch (action) {
        case 'snapshot_simd':
          data = await httpClient.get('/api/simd_diff/snapshot');
          break;
        case 'diff_simd_vectors':
          data = await httpClient.get('/api/simd_diff/compare');
          break;
        case 'get_vector_lanes':
          data = await httpClient.post('/api/simd_diff/lanes', { register_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
