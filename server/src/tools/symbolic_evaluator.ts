import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSymbolicEvaluatorTools(server: McpServer) {
  server.tool(
    'x64dbg_symbolic_evaluator',
    'Evaluate and simplify complex Mixed Boolean-Arithmetic (MBA) expressions, simplify obfuscated algebraic identity trees, and solve arithmetic equivalence.',
    {
      action: z.enum(['simplify_mba', 'evaluate_expression', 'solve_equivalence']).describe('Symbolic evaluation action'),
      expression: z.string().describe('Arithmetic/Boolean expression string to simplify or evaluate'),
      target_equivalence: z.string().optional().describe('Optional equivalence target string'),
    },
    async ({ action, expression, target_equivalence }) => {
      let data: unknown;
      switch (action) {
        case 'simplify_mba':
          data = await httpClient.post('/api/symbolic_eval/simplify_mba', { expression });
          break;
        case 'evaluate_expression':
          data = await httpClient.post('/api/symbolic_eval/evaluate', { expression });
          break;
        case 'solve_equivalence':
          data = await httpClient.post('/api/symbolic_eval/solve_equivalence', { expression, target_equivalence });
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
