import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerInstructionFusionAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_instruction_fusion_analyzer',
    'Identify macro-fusion (e.g. cmp+jne, test+je) and micro-fusion instruction pairs executed on Intel/AMD decoders.',
    {
      action: z.enum(['analyze_fusion_pairs', 'scan_basic_block_fusion', 'get_fusion_rules']).describe('Instruction fusion action'),
      address: z.string().optional().describe('Virtual address to analyze for fusion pairs'),
      count: z.number().default(16).describe('Number of instructions to inspect'),
    },
    async ({ action, address, count }) => {
      let data: unknown;
      switch (action) {
        case 'analyze_fusion_pairs':
          data = await httpClient.post('/api/macro_fusion/analyze', { address, count });
          break;
        case 'scan_basic_block_fusion':
          data = await httpClient.post('/api/macro_fusion/block', { address });
          break;
        case 'get_fusion_rules':
          data = await httpClient.get('/api/macro_fusion/rules');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
