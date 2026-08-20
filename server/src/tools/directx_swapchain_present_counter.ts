import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDirectxSwapchainPresentCounterTools(server: McpServer) {
  server.tool(
    'x64dbg_directx_swapchain_present_counter',
    'Count IDXGISwapChain Present() frame submissions, calculate rendering FPS, and measure frame presentation latencies.',
    {
      action: z.enum(['get_frame_stats', 'reset_counters', 'get_present_latency']).describe('Swapchain counter action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'get_frame_stats':
          data = await httpClient.get('/api/dx_present/stats');
          break;
        case 'reset_counters':
          data = await httpClient.post('/api/dx_present/reset', {});
          break;
        case 'get_present_latency':
          data = await httpClient.get('/api/dx_present/latency');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
