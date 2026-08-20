import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerThreadTools(server: McpServer) {
  server.tool(
    'x64dbg_threads',
    'Thread operations: list, get current/specific/teb/name, full multi-thread context snapshot, context read/write, or switch/suspend/resume. ' +
    'Actions: list (all threads), current, count, info (by TID), contexts_all (full multi-thread snapshot with CIP, TEB, and name), ' +
    'teb, name, switch (switch active thread), suspend, resume, ' +
    'context (get full thread context: GPRs, flags, segment registers, debug registers), ' +
    'context_set (set thread context registers by name/value).',
    {
      action: z.discriminatedUnion("action", [
        z.object({ action: z.literal("list") }),
        z.object({ action: z.literal("current") }),
        z.object({ action: z.literal("count") }),
        z.object({ action: z.literal("contexts_all") }),
        z.object({ action: z.literal("info"), tid: z.string().describe("Thread ID (decimal)") }),
        z.object({ action: z.literal("teb"), tid: z.string() }),
        z.object({ action: z.literal("name"), tid: z.string() }),
        z.object({ action: z.literal("switch"), id: z.string().describe("Thread ID (decimal)") }),
        z.object({ action: z.literal("suspend"), id: z.string() }),
        z.object({ action: z.literal("resume"), id: z.string() }),
        z.object({ action: z.literal("context"), tid: z.string().optional().describe("Thread ID (decimal, optional; defaults to current)") }),
        z.object({
          action: z.literal("context_set"),
          tid: z.string().optional().describe("Thread ID to switch to before setting registers (optional)"),
          rax: z.string().optional(), rbx: z.string().optional(), rcx: z.string().optional(),
          rdx: z.string().optional(), rsi: z.string().optional(), rdi: z.string().optional(),
          rbp: z.string().optional(), rsp: z.string().optional(), rip: z.string().optional(),
          r8: z.string().optional(), r9: z.string().optional(), r10: z.string().optional(),
          r11: z.string().optional(), r12: z.string().optional(), r13: z.string().optional(),
          r14: z.string().optional(), r15: z.string().optional(), eflags: z.string().optional()
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'list':
            data = await httpClient.get('/api/threads/list');
            break;
          case 'current':
            data = await httpClient.get('/api/threads/current');
            break;
          case 'count':
            data = await httpClient.get('/api/threads/count');
            break;
          case 'contexts_all':
            data = await httpClient.get('/api/threads/contexts_all');
            break;
          case 'info':
            data = await httpClient.get('/api/threads/get', { id: action.tid });
            break;
          case 'teb':
          case 'name':
            data = await httpClient.get(`/api/threads/${action.action}`, { tid: action.tid });
            break;
          case 'switch':
          case 'suspend':
          case 'resume':
            data = await httpClient.post(`/api/threads/${action.action}`, { id: action.id });
            break;
          case 'context':
            data = await httpClient.get('/api/threads/context', { tid: action.tid || '' });
            break;
          case 'context_set': {
            const body: Record<string, string> = {};
            if (action.tid) body.tid = action.tid;
            const regs = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','rip','r8','r9','r10','r11','r12','r13','r14','r15','eflags'] as const;
            for (const r of regs) {
              if ((action as any)[r]) body[r] = (action as any)[r];
            }
            data = await httpClient.post('/api/threads/context_set', body);
            break;
          }
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
