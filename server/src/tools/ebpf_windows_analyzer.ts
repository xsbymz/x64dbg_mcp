import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerEbpfWindowsAnalyzerTools(server: McpServer) {
  server.tool(
    'x64dbg_ebpf_windows_analyzer',
    'eBPF for Windows (ebpfcore.sys) program execution, verification, and BPF maps inspector.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('enum_programs')
        }),
        z.object({
          action: z.literal('dump_maps')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'enum_programs':
            data = await httpClient.post('/api/ebpf/enum_programs', {});
            break;
          case 'dump_maps':
            data = await httpClient.post('/api/ebpf/dump_maps', {});
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
