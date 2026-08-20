import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAntiDebugAdvancedTools(server: McpServer) {
  server.tool(
    'x64dbg_antidebug_advanced',
    'Advanced anti-debug and anti-VM detection: timing checks, hardware debug register detection, NtQuery hooks, exception handlers, and comprehensive VM detection.',
    {
      action: z.enum(['timing_checks', 'hardware_bp_detection', 'ntquery_hooks', 'exception_handlers', 'vm_detect', 'registry_artifacts', 'driver_check', 'cpuid_check']).describe('Detection type'),
      module: z.string().optional().describe('Module name (timing_checks action)')
    },
    async ({ action, module }) => {
      try {
        let data: unknown;
        const params: Record<string, string> = {};

        if (action === 'vm_detect' || action === 'registry_artifacts' || action === 'driver_check' || action === 'cpuid_check') {
          data = await httpClient.get(`/api/vm/${action}`);
        } else {
          if (module) params.module = module;
          data = await httpClient.get(`/api/antidebug/${action}`, params);
        }

        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
