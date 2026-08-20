import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRustHelperTools(server: McpServer) {
  server.tool(
    'x64dbg_rust_helper',
    'Rust binary analysis helper: demangles Rust v0 and legacy mangled symbols, inspects panic backtrace handlers, and decodes Rust slice/str/Vec memory layouts.',
    {
      action: z.enum(['demangle_symbol', 'find_panic_handlers', 'inspect_layout', 'scan_rust_artifacts']).describe('Rust analysis action'),
      symbol: z.string().optional().describe('Mangled Rust symbol name (e.g. _RNvNtCs...)'),
      address: z.string().optional().describe('Memory address of slice/str/Vec pointer'),
      module: z.string().optional().describe('Target module name'),
    },
    async ({ action, symbol, address, module }) => {
      let data: unknown;
      switch (action) {
        case 'demangle_symbol':
          data = await httpClient.post('/api/rust/demangle', { symbol });
          break;
        case 'find_panic_handlers':
          data = await httpClient.post('/api/rust/find_panic_handlers', { module });
          break;
        case 'inspect_layout':
          data = await httpClient.post('/api/rust/inspect_layout', { address });
          break;
        case 'scan_rust_artifacts':
          data = await httpClient.post('/api/rust/scan_artifacts', { module });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
