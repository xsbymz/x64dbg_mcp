import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerJitRopAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_jit_rop_analyzer',
    'JIT-ROP analysis engine for modern exploitation. Analyzes JIT code generation, identifies volatile gadgets, ' +
    'and builds JIT-resilient ROP chains. Supports modern JavaScript engines (V8, SpiderMonkey) and runtime code generation. ' +
    'Actions: analyze_jit_code (understand JIT memory layout), find_stable_gadgets (gadgets across code regeneration), ' +
    'build_jit_resilient_chain (chains that survive JIT changes).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('analyze_jit_code'),
          engine: z.enum(['v8', 'spidermonkey', 'chakra', 'auto_detect']).optional().default('auto_detect').describe('JavaScript engine'),
          include_memory_layout: z.boolean().optional().default(true).describe('Map JIT memory regions'),
          include_code_cache: z.boolean().optional().default(true).describe('Analyze code cache')
        }),
        z.object({
          action: z.literal('find_stable_gadgets'),
          stability_threshold: z.number().optional().default(0.95).describe('Threshold for stability (0-1)'),
          max_results: z.number().optional().default(20).describe('Max gadgets to return')
        }),
        z.object({
          action: z.literal('build_jit_resilient_chain'),
          target_effects: z.array(z.string()).describe('Desired effects (same as semantic synthesizer)'),
          allow_indirect: z.boolean().optional().default(true).describe('Allow indirect branches'),
          max_chain_length: z.number().optional().default(15).describe('Maximum chain length')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'analyze_jit_code':
            data = await httpClient.post('/api/jit/analyze_jit_code', {
              engine: action.engine,
              include_memory_layout: action.include_memory_layout,
              include_code_cache: action.include_code_cache
            });
            break;
          case 'find_stable_gadgets':
            data = await httpClient.post('/api/jit/find_stable_gadgets', {
              stability_threshold: action.stability_threshold,
              max_results: action.max_results
            });
            break;
          case 'build_jit_resilient_chain':
            data = await httpClient.post('/api/jit/build_resilient_chain', {
              target_effects: action.target_effects,
              allow_indirect: action.allow_indirect,
              max_chain_length: action.max_chain_length
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
