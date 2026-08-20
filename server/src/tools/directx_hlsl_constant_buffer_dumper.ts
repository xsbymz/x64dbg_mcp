import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDirectxHlslConstantBufferDumperTools(server: McpServer) {
  server.tool(
    'x64dbg_directx_hlsl_constant_buffer_dumper',
    'Dump DX11/DX12 ID3D11Buffer constant buffer slots (cbuffer b0-b13), shader parameter arrays, and matrix layouts.',
    {
      action: z.enum(['dump_cbuffer_slot', 'list_bound_cbuffers', 'format_as_matrices']).describe('Constant buffer action'),
      slot_index: z.number().min(0).max(13).optional().describe('Constant buffer slot index (0-13)'),
      cbuffer_ptr: z.string().optional().describe('Virtual address of constant buffer data'),
    },
    async ({ action, slot_index, cbuffer_ptr }) => {
      let data: unknown;
      switch (action) {
        case 'dump_cbuffer_slot':
          data = await httpClient.post('/api/dx_cbuffer/slot', { slot_index });
          break;
        case 'list_bound_cbuffers':
          data = await httpClient.get('/api/dx_cbuffer/list');
          break;
        case 'format_as_matrices':
          data = await httpClient.post('/api/dx_cbuffer/matrices', { cbuffer_ptr });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
