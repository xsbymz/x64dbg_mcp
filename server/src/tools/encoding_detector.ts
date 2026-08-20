import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerEncodingDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_encoding_detector',
    'Detect and decode data encodings (Base64, Base85, Hex, URL, Unicode, Rot13, Custom Alphabets) in memory buffers and registers.',
    {
      action: z.enum(['detect', 'decode', 'bruteforce']).describe('Encoding operation'),
      address: z.string().optional().describe('Address of encoded buffer'),
      length: z.number().optional().default(128),
      encoding: z.enum(['auto', 'base64', 'hex', 'rot13', 'base85', 'url']).optional().default('auto'),
    },
    async ({ action, address, length, encoding }) => {
      let data: unknown;
      switch (action) {
        case 'detect':
          data = await httpClient.post('/api/encoding/detect', { address, length });
          break;
        case 'decode':
          data = await httpClient.post('/api/encoding/decode', { address, length, encoding });
          break;
        case 'bruteforce':
          data = await httpClient.post('/api/encoding/bruteforce', { address, length });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
