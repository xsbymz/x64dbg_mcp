import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPdbSymbolDownloaderTools(server: McpServer) {
  server.tool(
    'x64dbg_pdb_symbol_downloader',
    'Download and cache PDB debug symbols from Microsoft Symbol Server / custom symbol paths using module GUID and age signatures.',
    {
      action: z.enum(['download_pdb', 'get_pdb_info', 'clear_symbol_cache']).describe('PDB symbol action'),
      module: z.string().optional().describe('Target module name'),
      symbol_server_url: z.string().optional().describe('Custom symbol server URL'),
    },
    async ({ action, module, symbol_server_url }) => {
      let data: unknown;
      switch (action) {
        case 'download_pdb':
          data = await httpClient.post('/api/pdb/download', { module, symbol_server_url });
          break;
        case 'get_pdb_info':
          data = await httpClient.post('/api/pdb/info', { module });
          break;
        case 'clear_symbol_cache':
          data = await httpClient.post('/api/pdb/clear_cache', {});
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
