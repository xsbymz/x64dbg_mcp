import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { httpClient } from '../http_client.js';

export function registerHalDispatchHijackAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_hal_dispatch_dump_table',
    'Dump HalDispatchTable and HalPrivateDispatchTable kernel function pointer arrays. Index 1 (HalQuerySystemInformation) is the classic kernel EoP overwrite target used in Stuxnet, CVE-2010-0270, and dozens of APT toolkits via the NtQueryIntervalProfile trigger gadget.',
    {},
    async () => {
      const result = await httpClient.post('/api/hal_dispatch/dump_table', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_hal_dispatch_validate_pointers',
    'Validate HalDispatchTable function pointers against the loaded kernel module map. Identifies any pointer that falls outside the valid address range of hal.dll, ntoskrnl.exe, halmacpi.dll, or halacpi.dll — indicating a rootkit or exploit overwrite.',
    {},
    async () => {
      const result = await httpClient.post('/api/hal_dispatch/validate_pointers', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_hal_dispatch_detect_overwrite',
    'Detect HAL dispatch table overwrites using multiple detection techniques: pointer range validation, trampoline stub detection (JMP [rip+0] patterns), and NtQueryIntervalProfile->HalDispatchTable[1] dispatch chain analysis. Returns CVE examples and known exploit patterns.',
    {},
    async () => {
      const result = await httpClient.post('/api/hal_dispatch/detect_overwrite', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );
}
