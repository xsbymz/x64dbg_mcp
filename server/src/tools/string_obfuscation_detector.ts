import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerStringObfuscationDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_string_obfuscation_detector',
    'Detect obfuscated and encrypted strings: identify stack strings constructed via MOV byte/dword sequences, XOR-encoded string tables, and rolling subtraction loops.',
    {
      action: z.enum(['scan_stack_strings', 'scan_xor_string_tables', 'scan_function_strings']).describe('String obfuscation action'),
      module: z.string().optional().describe('Target module name'),
      function_address: z.string().optional().describe('Target function virtual address'),
    },
    async ({ action, module, function_address }) => {
      let data: unknown;
      switch (action) {
        case 'scan_stack_strings':
          data = await httpClient.post('/api/str_obf/stack_strings', { module, function_address });
          break;
        case 'scan_xor_string_tables':
          data = await httpClient.post('/api/str_obf/xor_tables', { module });
          break;
        case 'scan_function_strings':
          data = await httpClient.post('/api/str_obf/function_strings', { function_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
