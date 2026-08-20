import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDelphiHelperTools(server: McpServer) {
  server.tool(
    'x64dbg_delphi_helper',
    'Reverse engineer Delphi / C++Builder VCL binaries: recover published VCL methods, event handlers (OnClick, OnCreate), VMT tables, and Delphi string descriptors.',
    {
      action: z.enum(['scan_vmt', 'list_event_handlers', 'extract_forms', 'find_delphi_strings']).describe('Delphi analysis operation'),
      module: z.string().optional().describe('Target module name'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'scan_vmt':
          data = await httpClient.post('/api/delphi/scan_vmt', { module });
          break;
        case 'list_event_handlers':
          data = await httpClient.post('/api/delphi/event_handlers', { module });
          break;
        case 'extract_forms':
          data = await httpClient.post('/api/delphi/extract_forms', { module });
          break;
        case 'find_delphi_strings':
          data = await httpClient.post('/api/delphi/strings', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
