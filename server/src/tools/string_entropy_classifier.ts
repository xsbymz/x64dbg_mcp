import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerStringEntropyClassifierTools(server: McpServer) {
  server.tool(
    'x64dbg_string_entropy_classifier',
    'Classify all in-memory strings into Base64, Hex tokens, GUIDs, URLs, FilePaths, Domains, or High-Entropy Encrypted Tokens using entropy scoring.',
    {
      action: z.enum(['classify_module_strings', 'scan_for_iocs', 'get_high_entropy_strings']).describe('String classifier action'),
      module_name: z.string().optional().describe('Target module name (optional)'),
      min_entropy: z.number().optional().describe('Minimum Shannon entropy threshold (0.0 to 8.0)'),
    },
    async ({ action, module_name, min_entropy }) => {
      let data: unknown;
      switch (action) {
        case 'classify_module_strings':
          data = await httpClient.post('/api/str_classify/all', { module_name, min_entropy });
          break;
        case 'scan_for_iocs':
          data = await httpClient.post('/api/str_classify/iocs', { module_name });
          break;
        case 'get_high_entropy_strings':
          data = await httpClient.post('/api/str_classify/high_entropy', { module_name, min_entropy });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
