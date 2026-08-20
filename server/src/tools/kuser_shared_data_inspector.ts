import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerKuserSharedDataInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_kuser_shared_dump_fields',
    'Live dump all KUSER_SHARED_DATA fields from 0x7FFE0000 (user-mode read-only shared kernel page). Returns TickCountMultiplier, NtBuildNumber, NtMajorVersion, NativeProcessorArchitecture, KdDebuggerEnabled/NotPresent, SystemCall dispatch method, TickCount, Cookie, and NtSystemRoot. Critical source for kernel info-leak exploitation.',
    {},
    async () => {
      const result = await httpClient.post('/api/kuser_shared/dump_fields', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_kuser_shared_detect_debugger_flags',
    'Read KdDebuggerEnabled (0x7FFE02D4) and KdDebuggerNotPresent (0x7FFE02D5) flags from KUSER_SHARED_DATA. These are the fastest kernel debugger detection primitives — faster than NtQuerySystemInformation and nearly impossible to intercept with standard API hooks. Returns bypass techniques and PEB.BeingDebugged cross-check.',
    {},
    async () => {
      const result = await httpClient.post('/api/kuser_shared/detect_debugger_flags', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_kuser_shared_monitor_tick_drift',
    'Sample KUSER_SHARED_DATA TickCount against QueryPerformanceCounter to detect hypervisor-induced timing jitter. High jitter (>2ms per 10ms sleep) indicates VM/hypervisor presence, hardware throttling, or malicious QPC spoofing. Also reads SystemCall dispatch method to detect Heaven\'s Gate conditions.',
    {
      iterations: z.number().optional().describe('Number of 10ms sample iterations (max 100, default 10)'),
    },
    async ({ iterations }) => {
      const result = await httpClient.post('/api/kuser_shared/monitor_tick_drift', { iterations: iterations ?? 10 });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );
}
