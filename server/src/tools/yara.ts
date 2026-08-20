import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerYaraTools(server: McpServer) {
  server.tool(
    'x64dbg_yara',
    'Generate YARA rules from memory regions and Sigma rules from observed API behavior. ' +
    'Actions: from_memory (generate YARA rule from memory region with strings and high-entropy byte patterns), ' +
    'from_behavior (generate Sigma detection rule from a list of observed API calls).',
    {
      action: z.enum(['from_memory', 'from_behavior']).describe('Rule generation type'),
      address: z.string().optional().describe('Memory address to scan (required for from_memory)'),
      size: z.number().optional().default(65536).describe('Bytes to scan (from_memory, max 1MB)'),
      rule_name: z.string().optional().describe('Rule name (from_memory)'),
      strings_only: z.boolean().optional().default(false).describe('Only extract strings, skip byte patterns (from_memory)'),
      apis: z.array(z.string()).optional().describe('Array of API names observed (required for from_behavior)'),
      rule_title: z.string().optional().describe('Sigma rule title (from_behavior)')
    },
    async ({ action, address, size, rule_name, strings_only, apis, rule_title }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'from_memory':
            if (!address) throw new Error('address is required for from_memory action');
            data = await httpClient.post('/api/yara/from_memory', {
              address,
              size,
              rule_name: rule_name || 'memory_rule',
              strings_only
            });
            break;
          case 'from_behavior':
            if (!apis || apis.length === 0) throw new Error('apis array is required for from_behavior action');
            data = await httpClient.post('/api/yara/from_behavior', {
              apis,
              rule_title: rule_title || 'api_behavior_rule'
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
