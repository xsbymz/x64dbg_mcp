import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerHardwareBreakpointEvasionDetectorTools(server: McpServer) {
  server.tool(
    'x64dbg_hardware_breakpoint_evasion_detector',
    'Detect thread context manipulation routines designed to wipe DR0-DR3 / DR7 hardware debug registers via NtSetContextThread or GetThreadContext manipulation.',
    {
      action: z.enum(['scan_context_tampering', 'audit_dr_registers', 'monitor_context_syscalls']).describe('HW BP evasion action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'scan_context_tampering':
          data = await httpClient.get('/api/hw_evasion/tampering');
          break;
        case 'audit_dr_registers':
          data = await httpClient.get('/api/hw_evasion/dr_state');
          break;
        case 'monitor_context_syscalls':
          data = await httpClient.get('/api/hw_evasion/syscalls');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
