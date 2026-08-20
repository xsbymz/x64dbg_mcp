import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';


export function registerDebugTools(server: McpServer) {
  server.tool(
    'x64dbg_debug',
    'Execute core debugger actions. ' +
    'Actions: run, pause, force_pause, step_into, step_over, step_out, stop_debug, restart_debug, ' +
    'run_to_address (run until a specific VA), ' +
    'state (get current debugger state + optional health check), ' +
    'wait_event (RECOMMENDED after run/step: blocks up to timeout_ms waiting for the debugger to pause at a breakpoint or exception — avoids polling state in a loop).',
    {
      action: z.discriminatedUnion("action", [
        z.object({ action: z.literal("run") }),
        z.object({ action: z.literal("pause") }),
        z.object({ action: z.literal("force_pause") }),
        z.object({ action: z.literal("step_into") }),
        z.object({ action: z.literal("step_over") }),
        z.object({ action: z.literal("step_out") }),
        z.object({ action: z.literal("stop_debug") }),
        z.object({ action: z.literal("restart_debug") }),
        z.object({
          action: z.literal("run_to_address"),
          address: z.string().describe("Target address to run to (hex or expression)")
        }),
        z.object({
          action: z.literal("state"),
          include_health: z.boolean().optional().describe("Also check plugin health/version")
        }),
        // NEW: long-poll for debug event instead of polling state
        z.object({
          action: z.literal("wait_event"),
          timeout_ms: z.number().optional().default(10000).describe(
            "Max milliseconds to wait for a debug event (breakpoint hit, exception, step complete). " +
            "Default 10000ms (10s). Max 60000ms (60s). Returns immediately if already paused."
          )
        })
      ])
    },
    async ({ action }) => {
      try {
        let endpoint = '';
        let payload: unknown = undefined;

        switch(action.action) {
          case 'run': endpoint = '/api/debug/run'; break;
          case 'pause': endpoint = '/api/debug/pause'; break;
          case 'force_pause': endpoint = '/api/debug/force_pause'; break;
          case 'step_into': endpoint = '/api/debug/step_into'; break;
          case 'step_over': endpoint = '/api/debug/step_over'; break;
          case 'step_out': endpoint = '/api/debug/step_out'; break;
          case 'stop_debug': endpoint = '/api/debug/stop'; break;
          case 'restart_debug': endpoint = '/api/debug/restart'; break;
          case 'run_to_address':
            endpoint = '/api/debug/run_to';
            payload = { address: action.address };
            break;
          case 'state': {
            const stateData = await httpClient.get('/api/debug/state');
            let result: Record<string, unknown> = { state: stateData };
            if (action.include_health) {
              try {
                result.health = await httpClient.get('/api/health');
              } catch (e) {
                result.health = { error: "Health check failed" };
              }
            }
            return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
          }
          case 'wait_event': {
            // Long-poll: block until debugger pauses or timeout
            const data = await httpClient.get('/api/events/wait', {
              timeout_ms: String(action.timeout_ms ?? 10000)
            });
            return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
          }
        }

        const data = await httpClient.post(endpoint, payload);
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
