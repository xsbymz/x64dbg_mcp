import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerPeResourceManifestParserTools(server: McpServer) {
  server.tool(
    'x64dbg_pe_resource_manifest_parser',
    'Parse and validate embedded XML Application Manifests (RT_MANIFEST) for requestedPrivileges, dpiAware, and OS compatibility GUIDs.',
    {
      action: z.enum(['parse_manifest_xml', 'get_execution_level', 'list_supported_os_guids']).describe('Manifest parser action'),
      module_name: z.string().optional().describe('Module name (defaults to primary module)'),
    },
    async ({ action, module_name }) => {
      let data: unknown;
      switch (action) {
        case 'parse_manifest_xml':
          data = await httpClient.post('/api/pe_manifest/parse', { module_name });
          break;
        case 'get_execution_level':
          data = await httpClient.post('/api/pe_manifest/level', { module_name });
          break;
        case 'list_supported_os_guids':
          data = await httpClient.post('/api/pe_manifest/os_guids', { module_name });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
