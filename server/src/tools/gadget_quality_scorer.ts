import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerGadgetQualityScorerTools(server: McpServer) {
  server.tool(
    'x64dbg_gadget_quality_scorer',
    'Advanced gadget quality and compatibility scoring. Rates gadgets by stability, reliability, and mitigation resistance. ' +
    'Considers register clobbering, side effects, and exploit prerequisites. ' +
    'Actions: score_gadget (rate single gadget), score_chain (rate entire chain), ' +
    'find_best_gadgets (find highest-quality gadgets for effect).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('score_gadget'),
          address: z.string().describe('Gadget address to score'),
          context_mitigations: z.array(z.enum(['aslr', 'dep', 'cfg', 'cfi', 'klee'])).optional().describe('Active mitigations'),
          target_effect: z.string().optional().describe('Desired effect (for context-aware scoring)')
        }),
        z.object({
          action: z.literal('score_chain'),
          gadget_addresses: z.array(z.string()).describe('Ordered list of gadget addresses'),
          chain_purpose: z.enum(['code_exec', 'info_leak', 'stack_pivot', 'syscall', 'arbitrary_write']).optional().describe('Chain purpose'),
          factors: z.array(z.enum(['register_clobbering', 'side_effects', 'mitigation_resistance', 'reliability'])).optional().describe('Scoring factors')
        }),
        z.object({
          action: z.literal('find_best_gadgets'),
          effect: z.string().describe('Desired effect (e.g., "rdi=rax; rsi=rbx; ret")'),
          quality_threshold: z.number().optional().default(0.75).describe('Minimum quality score (0-1)'),
          max_results: z.number().optional().default(5).describe('Max gadgets to return'),
          prefer_short: z.boolean().optional().default(true).describe('Prefer shorter gadgets')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'score_gadget':
            data = await httpClient.post('/api/gadget/score_gadget', {
              address: action.address,
              context_mitigations: action.context_mitigations,
              target_effect: action.target_effect
            });
            break;
          case 'score_chain':
            data = await httpClient.post('/api/gadget/score_chain', {
              gadget_addresses: action.gadget_addresses,
              chain_purpose: action.chain_purpose,
              factors: action.factors
            });
            break;
          case 'find_best_gadgets':
            data = await httpClient.post('/api/gadget/find_best_gadgets', {
              effect: action.effect,
              quality_threshold: action.quality_threshold,
              max_results: action.max_results,
              prefer_short: action.prefer_short
            });
            break;
        }
        
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
