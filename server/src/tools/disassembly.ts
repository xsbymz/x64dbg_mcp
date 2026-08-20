import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerDisassemblyTools(server: McpServer) {
  server.tool(
    'x64dbg_disassembly',
    'Disassemble or assemble instructions. ' +
    'Actions: at_address (disassemble N instructions from address), ' +
    'function (disassemble whole function at address), ' +
    'range (disassemble from start to end address/size — useful when you know the block boundaries), ' +
    'info (fast single-instruction info: size, is_branch, is_call), ' +
    'assemble (write a new instruction at an address).',
    {
      action: z.discriminatedUnion("action", [
        z.object({
          action: z.literal("at_address"),
          address: z.string().optional().default("cip").describe("Start address (default: current instruction pointer)"),
          count: z.string().optional().default("10").describe("Number of instructions to disassemble (max 1000)")
        }),
        z.object({
          action: z.literal("function"),
          address: z.string().optional().default("cip").describe("Any address inside the function (default: cip)"),
          max_instructions: z.number().optional().default(50).describe("Fallback instruction count when no function boundary exists (packed code)")
        }),
        // NEW: disassemble a known byte range without guessing instruction count
        z.object({
          action: z.literal("range"),
          start: z.string().describe("Start address (hex or expression)"),
          end: z.string().optional().describe("Exclusive end address — provide either 'end' or 'size'"),
          size: z.string().optional().describe("Byte count from start — provide either 'end' or 'size'")
        }),
        z.object({
          action: z.literal("info"),
          address: z.string().optional().default("cip").describe("Address of the instruction to inspect")
        }),
        z.object({
          action: z.literal("assemble"),
          address: z.string().describe("Target address to write the assembled bytes"),
          instruction: z.string().describe("Assembly instruction string (e.g. 'nop', 'jmp 0x401000', 'xor eax, eax')")
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'at_address':
            data = await httpClient.get('/api/disasm/at', { address: action.address, count: action.count });
            break;
          case 'function':
            data = await httpClient.get('/api/disasm/function', {
              address: action.address,
              max_instructions: String(action.max_instructions),
            });
            break;
          case 'range':
            data = await httpClient.get('/api/disasm/range', {
              start: action.start,
              ...(action.end  ? { end:  action.end  } : {}),
              ...(action.size ? { size: action.size } : {}),
            });
            break;
          case 'info':
            data = await httpClient.get('/api/disasm/basic', { address: action.address });
            break;
          case 'assemble':
            data = await httpClient.post('/api/disasm/assemble', { address: action.address, instruction: action.instruction });
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
