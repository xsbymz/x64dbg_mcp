import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerVulkanDx11Dx12HookScannerTools(server: McpServer) {
  server.tool(
    'x64dbg_vulkan_dx11_dx12_hook_scanner',
    'Inspect DirectX 11/12 (IDXGISwapChain::Present, ResizeBuffers) and Vulkan (vkQueuePresentKHR) function pointers for injected graphics overlays.',
    {
      action: z.enum(['scan_graphics_hooks', 'inspect_swapchain', 'list_overlay_modules']).describe('Graphics scanner action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'scan_graphics_hooks':
          data = await httpClient.get('/api/gfx_hook/scan');
          break;
        case 'inspect_swapchain':
          data = await httpClient.get('/api/gfx_hook/swapchain');
          break;
        case 'list_overlay_modules':
          data = await httpClient.get('/api/gfx_hook/overlays');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
