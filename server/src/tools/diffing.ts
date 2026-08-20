import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDiffingTools(server: McpServer) {
  server.tool(
    'x64dbg_diffing',
    'Binary diffing: compare in-memory modules against on-disk PE, compare sections, and list patches. ' +
    'Actions: memory_vs_disk (compare a loaded module against its on-disk image to detect modifications, hollowing, packing), ' +
    'pe_sections (compare sections between two modules), ' +
    'patches (list all current byte patches with original vs patched values).',
    {
      action: z.enum(['memory_vs_disk', 'pe_sections', 'patches']).describe('Diffing action'),
      module: z.string().optional().describe('Module name (required for memory_vs_disk and pe_sections)'),
      module2: z.string().optional().describe('Second module name (required for pe_sections)')
    },
    async ({ action, module, module2 }) => {
      try {
        let data: unknown;
        switch (action) {
          case 'memory_vs_disk':
            if (!module) throw new Error('module is required for memory_vs_disk action');
            data = await httpClient.post('/api/diff/memory_vs_disk', { module });
            break;
          case 'pe_sections':
            if (!module || !module2) throw new Error('module and module2 are required for pe_sections action');
            data = await httpClient.post('/api/diff/pe_sections', { module, module2: module2 });
            break;
          case 'patches':
            data = await httpClient.get('/api/diff/patches');
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
