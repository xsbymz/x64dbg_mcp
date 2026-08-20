import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryClassifierTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_classifier',
    'Classify memory regions by purpose and characteristics: heap, stack, module, shellcode, allocated, guard pages. ' +
    'Helps identify suspicious allocations, injected code, and abnormal memory usage patterns. ' +
    'Actions: classify_all (classify entire memory map), classify_region (classify specific region), ' +
    'find_anomalies (find suspicious patterns), identify_allocation (determine what allocated a region).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('classify_all'),
          include_private: z.boolean().optional().default(true).describe('Include private allocations'),
          include_image: z.boolean().optional().default(true).describe('Include module images'),
          include_mapped: z.boolean().optional().default(false).describe('Include mapped files')
        }),
        z.object({
          action: z.literal('classify_region'),
          address: z.string().describe('Address to classify (hex or expression)')
        }),
        z.object({
          action: z.literal('find_anomalies'),
          include_injected: z.boolean().optional().default(true).describe('Detect injected code'),
          include_detached: z.boolean().optional().default(true).describe('Detect hollowed/detached modules'),
          include_orphaned: z.boolean().optional().default(true).describe('Find orphaned heaps'),
          entropy_threshold: z.number().optional().default(7.0).describe('Entropy threshold for suspicious regions (0-8)')
        }),
        z.object({
          action: z.literal('identify_allocation'),
          address: z.string().describe('Address to trace back to allocation source'),
          trace_depth: z.number().optional().default(10).describe('Call stack depth to analyze')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'classify_all':
            data = await httpClient.post('/api/memory/classify_all', {
              include_private: action.include_private,
              include_image: action.include_image,
              include_mapped: action.include_mapped
            });
            break;
          case 'classify_region':
            data = await httpClient.get('/api/memory/classify_region', { address: action.address });
            break;
          case 'find_anomalies':
            data = await httpClient.post('/api/memory/find_anomalies', {
              include_injected: action.include_injected,
              include_detached: action.include_detached,
              include_orphaned: action.include_orphaned,
              entropy_threshold: action.entropy_threshold
            });
            break;
          case 'identify_allocation':
            data = await httpClient.post('/api/memory/identify_allocation', {
              address: action.address,
              trace_depth: action.trace_depth
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
