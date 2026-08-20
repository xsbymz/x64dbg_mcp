import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerBranchHeatmapExporterTools(server: McpServer) {
  server.tool(
    'x64dbg_branch_heatmap_exporter',
    'Export basic block execution heatmaps into interactive SVG or standalone HTML visualization formats with color-coded hit frequencies.',
    {
      action: z.enum(['export_svg_heatmap', 'export_html_report', 'get_hot_blocks']).describe('Heatmap exporter action'),
      function_address: z.string().optional().describe('Function start virtual address (optional)'),
    },
    async ({ action, function_address }) => {
      let data: unknown;
      switch (action) {
        case 'export_svg_heatmap':
          data = await httpClient.post('/api/branch_heatmap/svg', { function_address });
          break;
        case 'export_html_report':
          data = await httpClient.post('/api/branch_heatmap/html', { function_address });
          break;
        case 'get_hot_blocks':
          data = await httpClient.post('/api/branch_heatmap/hot_blocks', { function_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
