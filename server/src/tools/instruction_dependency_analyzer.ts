import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerInstructionDependencyAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_instruction_dependency_analyzer',
    'Compute RAW (Read-After-Write), WAR (Write-After-Read), and WAW register/memory data dependencies between instructions in a basic block.',
    {
      action: z.enum(['analyze_block_dependencies', 'get_critical_path_length', 'find_independent_instructions']).describe('Dependency action'),
      start_address: z.string().describe('Starting address of the basic block or range'),
      instruction_count: z.number().optional().describe('Number of instructions to analyze (default 16)'),
    },
    async ({ action, start_address, instruction_count }) => {
      let data: unknown;
      switch (action) {
        case 'analyze_block_dependencies':
          data = await httpClient.post('/api/inst_dep/analyze', { start_address, instruction_count });
          break;
        case 'get_critical_path_length':
          data = await httpClient.post('/api/inst_dep/critical_path', { start_address, instruction_count });
          break;
        case 'find_independent_instructions':
          data = await httpClient.post('/api/inst_dep/independent', { start_address, instruction_count });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
