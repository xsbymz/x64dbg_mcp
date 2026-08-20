import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSignatureGeneratorTools(server: McpServer) {
  server.tool(
    'x64dbg_signature_generator',
    'Automatically generate YARA rules, Sigma detection rules, and Snort network signatures from analyzed functions, memory regions, and behavior patterns.',
    {
      rule_type: z.enum(['yara', 'sigma', 'snort']).describe('Target rule format'),
      address: z.string().optional().describe('Function address or memory region start'),
      size: z.number().optional().default(128).describe('Byte length to generate pattern from'),
      rule_name: z.string().optional().default('Malware_Detection_Rule'),
    },
    async ({ rule_type, address, size, rule_name }) => {
      let data: unknown;
      switch (rule_type) {
        case 'yara':
          data = await httpClient.post('/api/signature/generate_yara', { address, size, rule_name });
          break;
        case 'sigma':
          data = await httpClient.post('/api/signature/generate_sigma', { rule_name });
          break;
        case 'snort':
          data = await httpClient.post('/api/signature/generate_snort', { rule_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
