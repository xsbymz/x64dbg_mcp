import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRopPayloadGeneratorTools(server: McpServer) {
  server.tool(
    'x64dbg_rop_payload_generator',
    'Generate formatted Python (pwntools / struct.pack), C char arrays, or raw binary ROP payload buffers from validated gadget address chains.',
    {
      action: z.enum(['generate_python_script', 'generate_c_payload', 'generate_raw_binary']).describe('ROP payload generator action'),
      gadget_chain: z.array(z.string()).describe('List of 64-bit/32-bit hex addresses and arguments'),
      bad_chars: z.string().optional().describe('Comma-separated list of disallowed byte hex values (e.g. 0x00,0x0A,0x0D)'),
    },
    async ({ action, gadget_chain, bad_chars }) => {
      let data: unknown;
      switch (action) {
        case 'generate_python_script':
          data = await httpClient.post('/api/rop_payload/python', { gadget_chain, bad_chars });
          break;
        case 'generate_c_payload':
          data = await httpClient.post('/api/rop_payload/c_array', { gadget_chain, bad_chars });
          break;
        case 'generate_raw_binary':
          data = await httpClient.post('/api/rop_payload/raw', { gadget_chain, bad_chars });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
