import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHeapGadgetFinderTools(server: McpServer) {
  server.tool(
    'x64dbg_heap_gadget_finder',
    'Specialized gadget finder for heap exploitation. Identifies heap-specific primitives: ' +
    'heap overflow gadgets, chunk metadata manipulation, heap spray assistance, and allocator-aware gadgets. ' +
    'Supports modern heap allocators (tcache, fastbin, unsorted bin exploitation). ' +
    'Actions: find_heap_gadgets (search for heap primitives), analyze_allocator (understand allocator behavior), ' +
    'find_exploit_path (heap overflow to code execution).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('find_heap_gadgets'),
          gadget_type: z.enum(['overflow', 'uaf', 'chunk_metadata', 'heap_spray', 'size_field_write', 'fd_bk_write']).describe('Type of heap gadget'),
          module: z.string().optional().describe('Module to scan (all if omitted)'),
          max_results: z.number().optional().default(15).describe('Max gadgets to return'),
          allocator: z.enum(['dlmalloc', 'ptmalloc', 'jemalloc', 'windows', 'any']).optional().default('any').describe('Target allocator type')
        }),
        z.object({
          action: z.literal('analyze_allocator'),
          heap_handle: z.string().optional().describe('Heap handle to analyze (or default if omitted)'),
          detect_protections: z.boolean().optional().default(true).describe('Detect heap protections (safe-unlink, etc)'),
          enumerate_chunks: z.boolean().optional().default(true).describe('List all chunks in heap')
        }),
        z.object({
          action: z.literal('find_exploit_path'),
          vuln_type: z.enum(['heap_overflow', 'use_after_free', 'double_free', 'integer_overflow']).describe('Vulnerability type'),
          trigger_point: z.string().optional().describe('Allocation/write address (optional hint)'),
          target: z.enum(['code_exec', 'arbitrary_read', 'arbitrary_write']).optional().default('code_exec').describe('End goal'),
          max_depth: z.number().optional().default(10).describe('Max steps to code execution')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'find_heap_gadgets':
            data = await httpClient.post('/api/heap/find_gadgets', {
              gadget_type: action.gadget_type,
              module: action.module,
              max_results: action.max_results,
              allocator: action.allocator
            });
            break;
          case 'analyze_allocator':
            data = await httpClient.post('/api/heap/analyze_allocator', {
              heap_handle: action.heap_handle,
              detect_protections: action.detect_protections,
              enumerate_chunks: action.enumerate_chunks
            });
            break;
          case 'find_exploit_path':
            data = await httpClient.post('/api/heap/find_exploit_path', {
              vuln_type: action.vuln_type,
              trigger_point: action.trigger_point,
              target: action.target,
              max_depth: action.max_depth
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
