import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerApiDependencyGraphTools(server: McpServer) {
  server.tool(
    'x64dbg_api_dependency_graph',
    'Build and analyze API call dependency graphs to understand malware behavior causality. ' +
    'Identifies prerequisite APIs, call chains, and attack workflows. ' +
    'Actions: build_graph (create dependency graph), analyze_chain (find behavior sequences), ' +
    'find_attack_workflow (identify exploitation/C2/persistence patterns).',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('build_graph'),
          include_all_calls: z.boolean().optional().default(true).describe('Include all API calls'),
          include_returns: z.boolean().optional().default(true).describe('Include call dependencies based on return values'),
          include_parameters: z.boolean().optional().default(true).describe('Include dependencies based on parameter flow'),
          limit: z.number().optional().default(500).describe('Max calls to analyze')
        }),
        z.object({
          action: z.literal('analyze_chain'),
          start_api: z.string().describe('Starting API name (e.g., "GetCurrentProcess")'),
          end_api: z.string().describe('Ending/target API (e.g., "CreateRemoteThread")'),
          max_depth: z.number().optional().default(10).describe('Maximum chain length')
        }),
        z.object({
          action: z.literal('find_attack_workflow'),
          pattern: z.enum(['persistence', 'injection', 'c2', 'exfiltration', 'privilege_escalation', 'lateral_movement']).describe('Workflow pattern to find'),
          confidence_threshold: z.number().optional().default(0.7).describe('Confidence threshold (0-1)')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        
        switch (action.action) {
          case 'build_graph':
            data = await httpClient.post('/api/behavior/api_dependency_graph', {
              include_all_calls: action.include_all_calls,
              include_returns: action.include_returns,
              include_parameters: action.include_parameters,
              limit: action.limit
            });
            break;
          case 'analyze_chain':
            data = await httpClient.post('/api/behavior/analyze_chain', {
              start_api: action.start_api,
              end_api: action.end_api,
              max_depth: action.max_depth
            });
            break;
          case 'find_attack_workflow':
            data = await httpClient.post('/api/behavior/find_attack_workflow', {
              pattern: action.pattern,
              confidence_threshold: action.confidence_threshold
            });
            break;
        }
        
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
