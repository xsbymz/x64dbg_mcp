import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

// Step schema reused for loop body / if branches
const StepSchema: z.ZodType<unknown> = z.lazy(() =>
  z.object({
    op:          z.string().describe('Operation name (see script_builtins for full list)'),
    address:     z.string().optional().describe('Target address (for bp, bp_hw, comment, label)'),
    expression:  z.string().optional().describe('Expression to evaluate (for eval, assert)'),
    name:        z.string().optional().describe('Variable name to store result (for eval)'),
    message:     z.string().optional().describe('Message to log (for log)'),
    expr:        z.string().optional().describe('Expression to log (for log)'),
    text:        z.string().optional().describe('Label/comment text'),
    count:       z.number().int().optional().describe('Iteration count (for loop) or step count'),
    wait_ms:     z.number().int().optional().describe('Milliseconds to wait for pause (for run)'),
    ms:          z.number().int().optional().describe('Milliseconds to sleep (for sleep)'),
    cmd:         z.string().optional().describe('x64dbg command string (for command op)'),
    hw_type:     z.enum(['x', 'r', 'w']).optional().describe('Hardware breakpoint type'),
    single_shot: z.boolean().optional().describe('Single-shot breakpoint (for bp)'),
    condition:   z.string().optional().describe('Break condition expression'),
    value:       z.number().optional().describe('Expected value (for assert)'),
    op_cmp:      z.enum(['eq', 'ne', 'gt', 'lt']).optional().describe('Comparison operator for assert'),
    left:        z.string().optional().describe('Left-hand expression (for if_eq)'),
    right:       z.number().optional().describe('Right-hand value (for if_eq)'),
    steps:       z.array(z.unknown()).optional().describe('Sub-steps (for loop)'),
    then:        z.array(z.unknown()).optional().describe('Steps to run if condition true (for if)'),
    else:        z.array(z.unknown()).optional().describe('Steps to run if condition false (for if)'),
    msg:         z.string().optional().describe('Assertion failure message'),
  })
);

export function registerScriptEngineTools(server: McpServer) {
  server.tool(
    'script_run',
    'Execute a debugging automation script defined as an array of steps. ' +
    'Supports: bp, bp_hw, bp_clear, run, step_into, step_over, step_out, eval, log, ' +
    'comment, label, assert, loop, if_eq, sleep, command. ' +
    'Returns a per-step execution log, any script variables set via eval, and a final register snapshot. ' +
    'Example: set a BP, run until hit, step 5 times, assert RAX != 0, log RCX.',
    {
      steps: z.array(StepSchema)
               .max(1000)
               .describe('Array of script step objects to execute in order'),
      stop_on_error: z.boolean().optional().default(false)
                      .describe('If true, stop script execution on first error'),
    },
    async ({ steps, stop_on_error }) => {
      const data = await httpClient.post('/api/script/run', { steps, stop_on_error });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'script_builtins',
    'List all supported script operation names and their parameter schemas for use with script_run.',
    {},
    async () => {
      const data = await httpClient.get('/api/script/builtins');
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
