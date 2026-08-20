import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCompressionDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_compression_detector',
    'Detect embedded compressed data streams (zlib, gzip, deflate, LZNT1, bzip2, LZMA, aPLib) in memory/PE sections and decompress or carve them.',
    {
      action: z.enum(['detect', 'decompress', 'carve']).describe('Compression analysis action'),
      address: z.string().optional().describe('Memory address of compressed data'),
      size: z.number().optional().default(1024),
      algorithm: z.enum(['auto', 'zlib', 'gzip', 'lznt1', 'deflate', 'lzma', 'aplib']).optional().default('auto'),
    },
    async ({ action, address, size, algorithm }) => {
      let data: unknown;
      switch (action) {
        case 'detect':
          data = await httpClient.post('/api/compression/detect', { address, size });
          break;
        case 'decompress':
          data = await httpClient.post('/api/compression/decompress', { address, size, algorithm });
          break;
        case 'carve':
          data = await httpClient.post('/api/compression/carve', { address, size });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
