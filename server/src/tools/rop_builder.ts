import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRopBuilderTools(server: McpServer) {
  server.tool(
    'x64dbg_rop_builder',
    'Advanced ROP chain construction and analysis. Build executable return-oriented programming chains from discovered gadgets. ' +
    'Actions: find_gadgets (search for gadgets by effect), build_chain (construct chain), validate_chain (test chain), ' +
    'export_chain (generate code for chain).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('find_gadgets'),
          effect: z.string().describe('Desired gadget effect (e.g., "rax=rbx", "rsp+=8", "call rax", "mov rdi, rax; ret")'),
          module: z.string().optional().describe('Restrict search to module'),
          max_results: z.number().optional().default(10).describe('Max gadgets to return')
        }),
        z.object({
          action: z.literal('build_chain'),
          gadgets: z.array(z.object({
            address: z.string().describe('Gadget address'),
            purpose: z.string().describe('What this gadget does in the chain (e.g., "load /bin/sh")'),
            args: z.record(z.string()).optional().describe('Register/memory setup for this gadget')
          })).describe('Ordered list of gadgets'),
          target: z.string().optional().describe('Target payload/behavior (e.g., "execute_shellcode", "leak_memory")')
        }),
        z.object({
          action: z.literal('validate_chain'),
          chain_address: z.string().describe('Starting address of ROP chain in memory'),
          chain_length: z.number().optional().default(100).describe('Number of QWORDS in chain')
        }),
        z.object({
          action: z.literal('export_chain'),
          gadgets: z.array(z.string()).describe('List of gadget addresses in order'),
          format: z.enum(['asm', 'c', 'python', 'c_shellcode']).optional().default('c').describe('Export format'),
          include_args: z.boolean().optional().default(true).describe('Include register setup')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'find_gadgets':
            data = await httpClient.post('/api/rop/find_gadgets', {
              effect: action.effect,
              module: action.module,
              max_results: action.max_results
            });
            break;
          case 'build_chain':
            data = await httpClient.post('/api/rop/build_chain', {
              gadgets: action.gadgets,
              target: action.target
            });
            break;
          case 'validate_chain':
            data = await httpClient.post('/api/rop/validate_chain', {
              chain_address: action.chain_address,
              chain_length: action.chain_length
            });
            break;
          case 'export_chain':
            data = await httpClient.post('/api/rop/export_chain', {
              gadgets: action.gadgets,
              format: action.format,
              include_args: action.include_args
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
