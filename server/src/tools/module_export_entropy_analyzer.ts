import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerModuleExportEntropyAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_module_export_entropy_analyzer',
    'Compute Shannon entropy and name distribution metrics of PE export tables to detect packed, encrypted, or obfuscated export names and ordinals.',
    {
      action: z.enum(['analyze_export_entropy', 'list_suspicious_export_names', 'get_ordinal_distribution']).describe('Export entropy action'),
      module_name: z.string().optional().describe('Loaded module name (optional)'),
    },
    async ({ action, module_name }) => {
      let data: unknown;
      switch (action) {
        case 'analyze_export_entropy':
          data = await httpClient.post('/api/export_entropy/analyze', { module_name });
          break;
        case 'list_suspicious_export_names':
          data = await httpClient.post('/api/export_entropy/suspicious', { module_name });
          break;
        case 'get_ordinal_distribution':
          data = await httpClient.post('/api/export_entropy/ordinals', { module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
