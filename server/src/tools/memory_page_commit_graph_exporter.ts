import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryPageCommitGraphExporterTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_page_commit_graph_exporter',
    'Export SVG/JSON timeline graphs of page commit, decommit, and protection shifts over debuggee execution steps.',
    {
      action: z.enum(['export_svg_timeline', 'get_commit_history', 'clear_history']).describe('Commit graph action'),
      format: z.enum(['svg', 'json']).default('svg').describe('Output format'),
      limit: z.number().default(50).describe('Max execution snapshots to include'),
    },
    async ({ action, format, limit }) => {
      let data: unknown;
      switch (action) {
        case 'export_svg_timeline':
          data = await httpClient.post('/api/commit_graph/export', { format, limit });
          break;
        case 'get_commit_history':
          data = await httpClient.get('/api/commit_graph/history');
          break;
        case 'clear_history':
          data = await httpClient.post('/api/commit_graph/clear', {});
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
