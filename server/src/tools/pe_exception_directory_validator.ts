import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeExceptionDirectoryValidatorTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_exception_directory_validator',
    'Validate the integrity and bounds of PE Exception Directory RVAs, function entry counts, and section alignment against on-disk headers.',
    {
      action: z.enum(['validate_exception_directory', 'check_runtime_function_bounds', 'detect_orphaned_unwind_info']).describe('Exception dir validator action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'validate_exception_directory':
          data = await httpClient.get('/api/pe_ex_dir/validate');
          break;
        case 'check_runtime_function_bounds':
          data = await httpClient.get('/api/pe_ex_dir/bounds');
          break;
        case 'detect_orphaned_unwind_info':
          data = await httpClient.get('/api/pe_ex_dir/orphans');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
