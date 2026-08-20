import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerWorkflowTools(server: McpServer) {
  server.tool(
    'x64dbg_vulnerability_assessment',
    'End-to-end vulnerability assessment workflow for a module. Chains multiple analysis steps: ' +
    '1) Scan for vulnerability patterns, 2) Check buffer overflow candidates, 3) Check format string vulnerabilities, ' +
    '4) Check integer overflow candidates, 5) Analyze stack canary protection, 6) Compute exploitability score.',
    {
      module: z.string().optional().describe('Module to analyze (default: module at CIP)')
    },
    async ({ module }) => {
      try {
        const results: Record<string, unknown> = {
          module: module || 'current_module',
          timestamp: new Date().toISOString()
        };

        try {
          results.pattern_scan = await httpClient.post('/api/vuln/scan_patterns', { module, limit: 100 });
        } catch (e) {
          results.pattern_scan_error = (e instanceof Error ? e.message : String(e));
        }

        try {
          results.buffer_overflow = await httpClient.post('/api/vuln/check_buffer_overflow', { function: 'cip' });
        } catch (e) {
          results.buffer_overflow_error = (e instanceof Error ? e.message : String(e));
        }

        try {
          results.format_string = await httpClient.post('/api/vuln/check_format_string', { function: 'cip' });
        } catch (e) {
          results.format_string_error = (e instanceof Error ? e.message : String(e));
        }

        try {
          results.integer_overflow = await httpClient.post('/api/vuln/check_integer_overflow', { function: 'cip' });
        } catch (e) {
          results.integer_overflow_error = (e instanceof Error ? e.message : String(e));
        }

        try {
          results.stack_canary = await httpClient.post('/api/vuln/stack_canary_check', { function: 'cip' });
        } catch (e) {
          results.stack_canary_error = (e instanceof Error ? e.message : String(e));
        }

        try {
          results.exploitability = await httpClient.post('/api/vuln/exploitability_score', { function: 'cip' });
        } catch (e) {
          results.exploitability_error = (e instanceof Error ? e.message : String(e));
        }

        const exploitabilityData = results.exploitability as { score?: number } | undefined;
        const hasHighRisk = exploitabilityData && typeof exploitabilityData === 'object' &&
          (exploitabilityData.score || 0) > 50;

        results.summary = {
          has_high_risk: hasHighRisk || false,
          risk_level: hasHighRisk ? 'HIGH' : 'MEDIUM',
          recommendation: hasHighRisk
            ? 'Module contains high-risk exploitable patterns. Review individual findings above.'
            : 'Module appears to have moderate or low exploitability. Review pattern scan for details.'
        };

        return { content: [{ type: 'text', text: JSON.stringify(results, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );

  server.tool(
    'x64dbg_rop_workflow',
    'End-to-end ROP exploit development workflow. Chains: 1) Find gadgets, 2) Build chain, 3) Validate chain.',
    {
      module: z.string().optional().describe('Module to search for gadgets'),
      target: z.string().optional().describe('Target behavior (e.g., "execute_shellcode", "leak_memory")'),
      max_gadgets: z.number().optional().default(20).describe('Maximum gadgets to find')
    },
    async ({ module, target, max_gadgets }) => {
      try {
        const results: Record<string, unknown> = {
          module: module || 'current_module',
          target: target || 'unknown',
          timestamp: new Date().toISOString()
        };

        try {
          results.gadgets = await httpClient.post('/api/rop/find_gadgets', {
            effect: 'pop; ret',
            module,
            max_results: max_gadgets
          });
        } catch (e) {
          results.gadgets_error = (e instanceof Error ? e.message : String(e));
        }

        if (results.gadgets && typeof results.gadgets === 'object' && !('error' in results.gadgets)) {
          const gadgets = (results.gadgets as { gadgets?: Array<{ address?: string }> }).gadgets || [];
          if (gadgets.length > 0) {
            try {
              results.chain = await httpClient.post('/api/rop/build_chain', {
                gadgets: gadgets.slice(0, 5).map((g) => ({
                  address: g.address || '0x0',
                  purpose: 'chain_element'
                })),
                target
              });
            } catch (e) {
              results.chain_error = (e instanceof Error ? e.message : String(e));
            }
          }
        }

        results.summary = {
          gadgets_found: results.gadgets && typeof results.gadgets === 'object' && !('error' in results.gadgets)
            ? ((results.gadgets as { gadgets?: unknown[] }).gadgets || []).length
            : 0,
          chain_built: !!(results.chain && !results.chain_error),
          recommendation: results.chain && !results.chain_error
            ? 'ROP chain generated. Validate with /api/rop/validate_chain before use.'
            : 'Insufficient gadgets or build failed. Try different effect or module.'
        };

        return { content: [{ type: 'text', text: JSON.stringify(results, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
