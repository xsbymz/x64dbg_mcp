import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDebugDirectoryParserTools(server: McpServer) {
  server.tool(
    'x64dbg_debug_directory_parser',
    'Parse the PE Debug Directory (IMAGE_DIRECTORY_ENTRY_DEBUG): CodeView (RSDS/NB10), POGO, Repro, ILTCG, MPX, VC Feature, and Extended DLL Characteristics.',
    {
      action: z.enum(['parse_debug_entries', 'get_codeview_info', 'inspect_repro_data']).describe('Debug directory action'),
      module: z.string().optional().describe('Target module name'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'parse_debug_entries':
          data = await httpClient.post('/api/debug_dir/entries', { module });
          break;
        case 'get_codeview_info':
          data = await httpClient.post('/api/debug_dir/codeview', { module });
          break;
        case 'inspect_repro_data':
          data = await httpClient.post('/api/debug_dir/repro', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
