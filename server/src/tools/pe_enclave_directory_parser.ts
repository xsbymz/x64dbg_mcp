import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeEnclaveDirectoryParserTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_enclave_directory_parser',
    'Parse IMAGE_DIRECTORY_ENTRY_ENCLAVE for Intel SGX / VBS secure enclaves, enclave imports, and policy flags.',
    {
      action: z.enum(['parse_enclave_header', 'list_enclave_imports', 'get_enclave_policy']).describe('Enclave action'),
      module_name: z.string().optional().describe('Module name (defaults to primary module)'),
    },
    async ({ action, module_name }) => {
      let data: unknown;
      switch (action) {
        case 'parse_enclave_header':
          data = await httpClient.post('/api/enclave_dir/header', { module_name });
          break;
        case 'list_enclave_imports':
          data = await httpClient.post('/api/enclave_dir/imports', { module_name });
          break;
        case 'get_enclave_policy':
          data = await httpClient.post('/api/enclave_dir/policy', { module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
