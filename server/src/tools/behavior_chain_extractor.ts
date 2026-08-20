import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerBehaviorChainExtractorTools(server: McpServer) {
  server.tool(
    'x64dbg_behavior_chain_extractor',
    'Extract temporal, causal, and contextual behavioral action chains from debugged execution (e.g. process creation, registry tampering, network beaconing).',
    {
      action: z.enum(['extract_chains', 'correlate_events', 'export_timeline']).describe('Analysis action to perform'),
      filter_category: z.enum(['all', 'process', 'filesystem', 'registry', 'network', 'injection']).optional().default('all'),
      max_events: z.number().optional().default(100),
    },
    async ({ action, filter_category, max_events }) => {
      let data: unknown;
      switch (action) {
        case 'extract_chains':
          data = await httpClient.post('/api/behavior/extract_chains', { filter_category, max_events });
          break;
        case 'correlate_events':
          data = await httpClient.post('/api/behavior/correlate_events', { max_events });
          break;
        case 'export_timeline':
          data = await httpClient.get('/api/behavior/export_timeline', { category: filter_category });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
