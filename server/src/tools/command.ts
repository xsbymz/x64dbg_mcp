import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCommandTools(server: McpServer) {
  server.tool(
    'x64dbg_command',
    'Execute x64dbg commands, scripts, evaluate expressions, and manage debug session. ' +
    'Actions: execute (run a single x64dbg command), script (run an array of commands in sequence), ' +
    'evaluate (evaluate one expression and return its value), ' +
    'evaluate_all (evaluate multiple named expressions in one call — efficient for fetching rip/rsp/registers/etc.), ' +
    'format (format a string using x64dbg expression engine), ' +
    'set_init_script / get_init_script (manage the debuggee startup script), ' +
    'get_hash (get database hash), get_events (get debug event count), get_log (get debug events and state status).',
    {
      action: z.discriminatedUnion("action", [
        z.object({
          action: z.literal("execute"),
          command: z.string().describe("x64dbg command string (e.g. 'bp 0x401000', 'run', 'analyze')")
        }),
        z.object({
          action: z.literal("script"),
          commands: z.array(z.string()).describe("Array of x64dbg commands to execute in sequence")
        }),
        z.object({
          action: z.literal("evaluate"),
          expression: z.string().describe("x64dbg expression to evaluate (e.g. 'rax', 'mod.entry(main)', '0x401000+10')")
        }),
        z.object({
          action: z.literal("evaluate_all"),
          expressions: z.record(z.string()).describe(
            "Named dictionary of expressions to evaluate. " +
            "E.g. { 'rip': 'cip', 'rsp': 'csp', 'retaddr': '[rsp]' }. " +
            "Returns all results in one call."
          )
        }),
        z.object({
          action: z.literal("format"),
          format: z.string().describe("Format string using x64dbg expression engine (e.g. '{rax} {rbx}')")
        }),
        z.object({
          action: z.literal("set_init_script"),
          file: z.string().describe("Path to .x64dbg_script file to run on debuggee start")
        }),
        z.object({ action: z.literal("get_init_script") }),
        z.object({ action: z.literal("get_hash") }),
        z.object({ action: z.literal("get_events") }),
        z.object({ action: z.literal("get_log") }),
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'execute':
            data = await httpClient.post('/api/command/exec', { command: action.command });
            break;
          case 'script':
            data = await httpClient.post('/api/command/script', { commands: action.commands });
            break;
          case 'evaluate':
            data = await httpClient.post('/api/command/eval', { expression: action.expression });
            break;
          case 'evaluate_all':
            data = await httpClient.post('/api/command/evaluate_all', { expressions: action.expressions });
            break;
          case 'format':
            data = await httpClient.post('/api/command/format', { format: action.format });
            break;
          case 'set_init_script':
            data = await httpClient.post('/api/command/init_script', { file: action.file });
            break;
          case 'get_init_script':
            data = await httpClient.get('/api/command/init_script');
            break;
          case 'get_hash':
            data = await httpClient.get('/api/command/hash');
            break;
          case 'get_events':
            data = await httpClient.get('/api/command/events');
            break;
          case 'get_log':
            data = await httpClient.get('/api/command/log');
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
