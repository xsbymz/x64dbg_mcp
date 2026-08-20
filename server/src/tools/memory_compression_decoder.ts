import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryCompressionDecoderTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_compression_decoder',
    'Windows Memory Compression (MemCompression) store inspector and LZ4/Xpress page decompressor.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('store_status')
        }),
        z.object({
          action: z.literal('decompress_page')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'store_status':
            data = await httpClient.post('/api/mem_compression/store_status', {});
            break;
          case 'decompress_page':
            data = await httpClient.post('/api/mem_compression/decompress_page', {});
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
