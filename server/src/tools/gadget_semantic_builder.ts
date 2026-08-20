import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerGadgetSemanticBuilderTools(server: McpServer) {
  server.tool(
    'x64dbg_semantic_gadget_builder',
    'Semantic ROP chain synthesis engine. Build executable ROP chains from high-level constraints instead of manual gadget selection. ' +
    'Automatically synthesizes gadget sequences to achieve target effects: load values, manipulate registers, execute syscalls. ' +
    'Actions: synthesize (build chain from effects), validate_synthesis (test generated chain), optimize_chain (reduce gadget count).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('synthesize'),
          target_effects: z.array(z.string()).describe('Desired effects in order (e.g., ["rdi=argv[0]", "rsi=0", "rdx=length", "call execve"])'),
          module: z.string().optional().describe('Module to search gadgets in (or all if omitted)'),
          max_gadgets: z.number().optional().default(10).describe('Maximum gadgets in output chain'),
          mitigations: z.array(z.enum(['aslr', 'dep', 'cfg', 'cfi'])).optional().describe('Mitigations to work around'),
          timeout_ms: z.number().optional().default(5000).describe('Solver timeout in milliseconds')
        }),
        z.object({
          action: z.literal('validate_synthesis'),
          chain_gadgets: z.array(z.string()).describe('List of gadget addresses to validate as chain'),
          trace_execution: z.boolean().optional().default(true).describe('Trace execution to verify behavior')
        }),
        z.object({
          action: z.literal('optimize_chain'),
          chain_gadgets: z.array(z.string()).describe('Current chain to optimize'),
          target_length: z.number().optional().describe('Desired chain length (shorter is better)'),
          preserve_semantics: z.boolean().optional().default(true).describe('Keep same semantic behavior')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'synthesize':
            data = await httpClient.post('/api/rop/semantic_synthesize', {
              target_effects: action.target_effects,
              module: action.module,
              max_gadgets: action.max_gadgets,
              mitigations: action.mitigations,
              timeout_ms: action.timeout_ms
            });
            break;
          case 'validate_synthesis':
            data = await httpClient.post('/api/rop/validate_synthesis', {
              chain_gadgets: action.chain_gadgets,
              trace_execution: action.trace_execution
            });
            break;
          case 'optimize_chain':
            data = await httpClient.post('/api/rop/optimize_chain', {
              chain_gadgets: action.chain_gadgets,
              target_length: action.target_length,
              preserve_semantics: action.preserve_semantics
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
