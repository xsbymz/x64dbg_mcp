import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeBoundImportDirectoryParserTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_bound_import_directory_parser',
    'Parse IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (IMAGE_BOUND_IMPORT_DESCRIPTOR, TimeDateStamp, ModuleName, and IMAGE_BOUND_FORWARDER_REF entries).',
    {
      action: z.enum(['parse_bound_imports', 'list_bound_modules', 'verify_timestamps']).describe('Bound import action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'parse_bound_imports':
          data = await httpClient.get('/api/bound_imports/parse');
          break;
        case 'list_bound_modules':
          data = await httpClient.get('/api/bound_imports/modules');
          break;
        case 'verify_timestamps':
          data = await httpClient.get('/api/bound_imports/verify');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
