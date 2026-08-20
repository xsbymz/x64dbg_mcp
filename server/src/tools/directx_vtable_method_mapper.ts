import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDirectxVtableMethodMapperTools(server: McpServer) {
  server.tool(
    'x64dbg_directx_vtable_method_mapper',
    'Map all IDXGISwapChain, ID3D11DeviceContext, and ID3D12CommandQueue VTable method indices and function addresses.',
    {
      action: z.enum(['map_dxgi_swapchain_vtable', 'map_d3d11_context_vtable', 'map_d3d12_queue_vtable']).describe('DirectX mapper action'),
      interface_address: z.string().optional().describe('Address of the COM interface instance'),
    },
    async ({ action, interface_address }) => {
      let data: unknown;
      switch (action) {
        case 'map_dxgi_swapchain_vtable':
          data = await httpClient.post('/api/dx_vtable/swapchain', { interface_address });
          break;
        case 'map_d3d11_context_vtable':
          data = await httpClient.post('/api/dx_vtable/d3d11', { interface_address });
          break;
        case 'map_d3d12_queue_vtable':
          data = await httpClient.post('/api/dx_vtable/d3d12', { interface_address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
