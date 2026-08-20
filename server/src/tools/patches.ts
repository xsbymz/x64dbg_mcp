import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPatchTools(server: McpServer) {
  server.tool(
    'x64dbg_patches',
    'List, apply, restore patches, or export patches as code stubs or patched binary files. ' +
    'Actions: list (list all byte patches), apply (write a byte patch), restore (restore original bytes at address), ' +
    'export (export patches as C/C++ memory patch stub, Python/Frida script, x64dbg script, or commit directly to a binary file on disk).',
    {
      action: z.discriminatedUnion("action", [
        z.object({ action: z.literal("list") }),
        z.object({
          action: z.literal("apply"),
          address: z.string().describe("Target address to patch (hex or expression)"),
          bytes: z.string().describe("New hex bytes to write (e.g. '90 90' or 'C3')")
        }),
        z.object({
          action: z.literal("restore"),
          address: z.string().describe("Address to restore to its original unpatched bytes")
        }),
        z.object({
          action: z.literal("export"),
          format: z.enum(['c_stub', 'python', 'x64dbg_script', 'file']).optional().default('x64dbg_script').describe(
            'Export format: c_stub (C/C++ WriteProcessMemory function), python (Python/Frida patch array), x64dbg_script (x64dbg setbyte commands), or file (commit patches directly to a new .exe/.dll file on disk)'
          ),
          module: z.string().optional().describe('Filter patches by module name (optional)'),
          path: z.string().optional().describe('Destination file path (required only when format is "file")')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'list':
            data = await httpClient.get('/api/patches/list');
            break;
          case 'apply':
            data = await httpClient.post('/api/patches/apply', { address: action.address, bytes: action.bytes });
            break;
          case 'restore':
            data = await httpClient.post('/api/patches/restore', { address: action.address });
            break;
          case 'export': {
            const body: Record<string, unknown> = {
              format: action.format
            };
            if (action.module) body.module = action.module;
            if (action.path) body.path = action.path;
            data = await httpClient.post('/api/patches/export', body);
            break;
          }
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
