import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerImportForgeTools(server: McpServer) {
  server.tool(
    'x64dbg_import_forge',
    'Manipulate imports and import address table (IAT). Redirect function calls, hook imports, or forge new imports for code injection. ' +
    'Actions: list_imports (enumerate IAT), redirect_import (change import target), hook_import (set API hook), restore_imports (undo IAT modifications).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('list_imports'),
          module: z.string().optional().describe('Module name (e.g., "kernel32.dll", or current module if omitted)'),
          include_forwarded: z.boolean().optional().default(true).describe('Include forwarded imports')
        }),
        z.object({
          action: z.literal('redirect_import'),
          module: z.string().describe('Module that has the import (e.g., "target.exe")'),
          api_name: z.string().describe('API name to redirect (e.g., "CreateFileA")'),
          source_module: z.string().describe('Original module (e.g., "kernel32.dll")'),
          new_address: z.string().describe('New address to call (hex or expression)'),
          permanent: z.boolean().optional().default(false).describe('Patch binary or just modify in-memory')
        }),
        z.object({
          action: z.literal('hook_import'),
          api_name: z.string().describe('API to hook (e.g., "GetProcAddress")'),
          hook_address: z.string().describe('Address of hook stub/trampoline'),
          method: z.enum(['iat_redirect', 'inline_jmp', 'trampoline']).optional().default('iat_redirect').describe('Hooking method'),
          log_calls: z.boolean().optional().default(true).describe('Log calls to this API')
        }),
        z.object({
          action: z.literal('restore_imports'),
          module: z.string().optional().describe('Module to restore (all if omitted)')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'list_imports':
            data = await httpClient.get('/api/import_forge/list', { 
              module: action.module || '',
              include_forwarded: String(action.include_forwarded)
            });
            break;
          case 'redirect_import':
            data = await httpClient.post('/api/import_forge/redirect', {
              module: action.module,
              api_name: action.api_name,
              source_module: action.source_module,
              new_address: action.new_address,
              permanent: action.permanent
            });
            break;
          case 'hook_import':
            data = await httpClient.post('/api/import_forge/hook', {
              api_name: action.api_name,
              hook_address: action.hook_address,
              method: action.method,
              log_calls: action.log_calls
            });
            break;
          case 'restore_imports':
            data = await httpClient.post('/api/import_forge/restore', {
              module: action.module || 'all'
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
