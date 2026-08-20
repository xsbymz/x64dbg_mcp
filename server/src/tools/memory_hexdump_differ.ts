import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerMemoryHexdumpDifferTools(server: McpServer) {
  server.tool(
    'x64dbg_memory_hexdump_differ',
    'Compare two arbitrary virtual memory buffers byte-by-byte and generate aligned side-by-side hexadecimal diffs highlighting modified bytes.',
    {
      action: z.enum(['diff_memory_buffers', 'get_mismatch_offsets', 'generate_patch_from_diff']).describe('Hexdump differ action'),
      buffer1_address: z.string().describe('Virtual address of first memory buffer'),
      buffer2_address: z.string().describe('Virtual address of second memory buffer'),
      size: z.number().describe('Size in bytes to compare'),
    },
    async ({ action, buffer1_address, buffer2_address, size }) => {
      let data: unknown;
      switch (action) {
        case 'diff_memory_buffers':
          data = await httpClient.post('/api/hexdump_diff/compare', { buffer1_address, buffer2_address, size });
          break;
        case 'get_mismatch_offsets':
          data = await httpClient.post('/api/hexdump_diff/mismatches', { buffer1_address, buffer2_address, size });
          break;
        case 'generate_patch_from_diff':
          data = await httpClient.post('/api/hexdump_diff/generate_patch', { buffer1_address, buffer2_address, size });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
