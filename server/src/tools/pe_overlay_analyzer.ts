import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeOverlayAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_overlay_analyzer',
    'Inspect and carve PE file overlays (data appended past PE image headers), detect embedded zip/cab archives, and verify digital signature padding.',
    {
      action: z.enum(['detect_overlay', 'carve_overlay', 'inspect_signatures', 'calculate_entropy']).describe('Overlay analysis action'),
      module: z.string().optional().describe('Target module name (defaults to main binary)'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'detect_overlay':
          data = await httpClient.post('/api/pe/overlay/detect', { module });
          break;
        case 'carve_overlay':
          data = await httpClient.post('/api/pe/overlay/carve', { module });
          break;
        case 'inspect_signatures':
          data = await httpClient.post('/api/pe/overlay/signatures', { module });
          break;
        case 'calculate_entropy':
          data = await httpClient.post('/api/pe/overlay/entropy', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
