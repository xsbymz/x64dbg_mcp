import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerLoadConfigDirectoryTools(server: McpServer) {
  server.tool(
    'x64dbg_load_config_directory',
    'Parse the PE Load Config Directory (IMAGE_LOAD_CONFIG_DIRECTORY64): CFG GuardFlags, SecurityCookie address, SEH Handler table, Enclave metadata, and CET shadow stack metadata.',
    {
      action: z.enum(['parse_load_config', 'get_guard_flags', 'get_security_cookie']).describe('Load config action'),
      module: z.string().optional().describe('Target module name'),
    },
    async ({ action, module }) => {
      let data: unknown;
      switch (action) {
        case 'parse_load_config':
          data = await httpClient.post('/api/load_config/parse', { module });
          break;
        case 'get_guard_flags':
          data = await httpClient.post('/api/load_config/guard_flags', { module });
          break;
        case 'get_security_cookie':
          data = await httpClient.post('/api/load_config/security_cookie', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
