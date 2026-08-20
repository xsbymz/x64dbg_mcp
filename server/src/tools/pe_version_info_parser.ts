import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeVersionInfoParserTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_version_info_parser',
    'Extract and parse VS_VERSIONINFO, StringFileInfo, VarFileInfo, ProductVersion, FileVersion, CompanyName, and LegalCopyright metadata fields.',
    {
      action: z.enum(['parse_version_info', 'list_string_file_info_keys', 'get_fixed_file_info']).describe('Version info action'),
      module_name: z.string().optional().describe('Target loaded module name (optional)'),
    },
    async ({ action, module_name }) => {
      let data: unknown;
      switch (action) {
        case 'parse_version_info':
          data = await httpClient.post('/api/pe_version/parse', { module_name });
          break;
        case 'list_string_file_info_keys':
          data = await httpClient.post('/api/pe_version/string_keys', { module_name });
          break;
        case 'get_fixed_file_info':
          data = await httpClient.post('/api/pe_version/fixed_info', { module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
