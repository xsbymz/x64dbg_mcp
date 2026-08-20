import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDirectxShaderBytecodeExtractorTools(server: McpServer) {
  server.tool(
    'x64dbg_directx_shader_bytecode_extractor',
    'Extract compiled HLSL DXBC (DirectX Bytecode) / DXIL shader objects from memory dumps and disassemble shader stages.',
    {
      action: z.enum(['scan_shaders', 'extract_dxbc_header', 'disassemble_shader']).describe('Shader extractor action'),
      address: z.string().optional().describe('Address of the shader bytecode buffer (DXBC magic 0x43425844)'),
    },
    async ({ action, address }) => {
      let data: unknown;
      switch (action) {
        case 'scan_shaders':
          data = await httpClient.get('/api/shader_extract/scan');
          break;
        case 'extract_dxbc_header':
          data = await httpClient.post('/api/shader_extract/header', { address });
          break;
        case 'disassemble_shader':
          data = await httpClient.post('/api/shader_extract/disasm', { address });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
