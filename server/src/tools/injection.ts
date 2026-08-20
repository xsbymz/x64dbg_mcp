import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerInjectionTools(server: McpServer) {
  server.tool(
    'x64dbg_injection',
    'Code injection and modification helpers: code cave detection, payload injection, and DLL injection setup. ' +
    'Actions: find_caves (locate code injection points), inject_code (write shellcode/code), inject_dll (set up DLL injection via multiple methods).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('find_caves'),
          min_size: z.number().optional().default(32).describe('Minimum cave size in bytes'),
          module: z.string().optional().describe('Restrict to specific module (e.g., "target.exe")'),
          executable_only: z.boolean().optional().default(true).describe('Only search in executable sections')
        }),
        z.object({
          action: z.literal('inject_code'),
          address: z.string().describe('Target address to inject at (hex or expression)'),
          bytes: z.string().describe('Hex bytes to inject (e.g., "90 90 CC")'),
          create_bp: z.boolean().optional().default(true).describe('Set breakpoint at injection point'),
          save_original: z.boolean().optional().default(true).describe('Save original bytes for restoration')
        }),
        z.object({
          action: z.literal('inject_dll'),
          dll_path: z.string().describe('Full path to DLL to inject (e.g., "C:\\\\inject.dll")'),
          method: z.enum(['createremotethread', 'apc', 'ntmapviewofsection', 'setwindowshookex']).optional().default('createremotethread').describe('Injection method'),
          module_to_load: z.string().optional().describe('Alternative DLL to load via injection stub'),
          immediate: z.boolean().optional().default(true).describe('Execute injection immediately or just set up hooks')
        }),
        z.object({
          action: z.literal('list_caves'),
          module: z.string().optional().describe('List previously found caves for module')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'find_caves':
            data = await httpClient.post('/api/injection/find_caves', {
              min_size: action.min_size,
              module: action.module,
              executable_only: action.executable_only
            });
            break;
          case 'inject_code':
            data = await httpClient.post('/api/injection/inject_code', {
              address: action.address,
              bytes: action.bytes,
              create_bp: action.create_bp,
              save_original: action.save_original
            });
            break;
          case 'inject_dll':
            data = await httpClient.post('/api/injection/inject_dll', {
              dll_path: action.dll_path,
              method: action.method,
              module_to_load: action.module_to_load,
              immediate: action.immediate
            });
            break;
          case 'list_caves':
            data = await httpClient.get('/api/injection/list_caves', { module: action.module || '' });
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
