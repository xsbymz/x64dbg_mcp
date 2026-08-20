import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCodeSimilarityEngineTools(server: McpServer) {
  server.tool(
    'x64dbg_code_similarity_engine',
    'Compare function control-flow graphs, basic block semantics, and compute fuzzy hashes (ssdeep / TLSH / MinHash) to match code variants across modules and binaries.',
    {
      action: z.enum(['compare_functions', 'find_clones', 'fuzzy_hash']).describe('Similarity analysis action'),
      target_address: z.string().describe('Target function address'),
      reference_address: z.string().optional().describe('Reference function address (for comparison)'),
      threshold: z.number().optional().default(0.75).describe('Minimum similarity score threshold (0.0 to 1.0)'),
    },
    async ({ action, target_address, reference_address, threshold }) => {
      let data: unknown;
      switch (action) {
        case 'compare_functions':
          data = await httpClient.post('/api/similarity/compare_functions', { target_address, reference_address });
          break;
        case 'find_clones':
          data = await httpClient.post('/api/similarity/find_clones', { target_address, threshold });
          break;
        case 'fuzzy_hash':
          data = await httpClient.post('/api/similarity/fuzzy_hash', { target_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
