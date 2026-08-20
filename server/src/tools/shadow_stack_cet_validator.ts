import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerShadowStackCetValidatorTools(server: McpServer) {
  server.tool(
    'x64dbg_shadow_stack_cet_validator',
    'Validate that return addresses on the active CPU Call Stack strictly match the Intel Control-flow Enforcement Technology (CET) Hardware Shadow Stack.',
    {
      action: z.enum(['validate_call_stack_vs_ssp', 'get_shadow_stack_frames', 'detect_ssp_mismatches']).describe('Shadow Stack action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'validate_call_stack_vs_ssp':
          data = await httpClient.get('/api/cet_shadow/validate');
          break;
        case 'get_shadow_stack_frames':
          data = await httpClient.get('/api/cet_shadow/frames');
          break;
        case 'detect_ssp_mismatches':
          data = await httpClient.get('/api/cet_shadow/mismatches');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
