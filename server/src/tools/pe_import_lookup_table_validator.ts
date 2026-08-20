import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeImportLookupTableValidatorTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_import_lookup_table_validator',
    'Validate synchronization and matching between PE Import Lookup Table (ILT / Hint/Name entries) and Import Address Table (IAT).',
    {
      action: z.enum(['validate_ilt_iat_parity', 'list_unmatched_thunks', 'check_ordinal_imports']).describe('ILT validator action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'validate_ilt_iat_parity':
          data = await httpClient.get('/api/ilt_val/parity');
          break;
        case 'list_unmatched_thunks':
          data = await httpClient.get('/api/ilt_val/unmatched');
          break;
        case 'check_ordinal_imports':
          data = await httpClient.get('/api/ilt_val/ordinals');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
