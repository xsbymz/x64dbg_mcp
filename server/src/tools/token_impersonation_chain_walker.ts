import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerTokenImpersonationChainWalkerTools(server: McpServer) {
  server.tool(
    'x64dbg_token_chain_walk_impersonation',
    'Walk the complete token impersonation chain across all threads in a process. Identifies threads with impersonation tokens, impersonation level (Anonymous/Identification/Impersonation/Delegation), impersonated user SID and domain\\username. Flags CRITICAL: SecurityDelegation-level impersonation allows full Kerberos double-hop.',
    {
      pid: z.number().optional().describe('Target process ID (default: current process)'),
    },
    async ({ pid }) => {
      const result = await httpClient.post('/api/token_chain/walk_impersonation', { pid: pid ?? 0 });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_token_chain_map_ancestry_dag',
    'Map the token ancestry DAG for a process. Returns token type (Primary/Impersonation), process user SID and domain\\username, token LUID, authentication LUID (logon session), modified LUID, integrity level (Untrusted/Low/Medium/High/System), and token creation time. Provides methodology for full cross-process ancestry reconstruction via LSASS LUID correlation.',
    {
      pid: z.number().optional().describe('Target process ID (default: current process)'),
    },
    async ({ pid }) => {
      const result = await httpClient.post('/api/token_chain/map_ancestry_dag', { pid: pid ?? 0 });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_token_chain_detect_escalation_paths',
    'Detect privilege escalation paths in a process token. Identifies present-but-disabled dangerous privileges: SeDebugPrivilege (LSASS access), SeLoadDriverPrivilege (kernel code exec), SeImpersonatePrivilege (RottenPotato/PrintSpoofer EoP), SeTcbPrivilege (arbitrary token creation), SeAssignPrimaryTokenPrivilege (SYSTEM process spawn). Present-but-disabled privs can often be re-enabled via AdjustTokenPrivileges without elevation.',
    {
      pid: z.number().optional().describe('Target process ID (default: current process)'),
    },
    async ({ pid }) => {
      const result = await httpClient.post('/api/token_chain/detect_escalation_paths', { pid: pid ?? 0 });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );
}
