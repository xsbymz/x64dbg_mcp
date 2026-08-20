import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { httpClient } from '../http_client.js';

export function registerWfpCalloutAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_wfp_enumerate_callouts',
    'Enumerate all Windows Filtering Platform (WFP) callout objects via FwpmCalloutEnum0. Returns callout GUIDs, names, applicable layer (INBOUND_IPPACKET, STREAM, ALE_AUTH_CONNECT, DATAGRAM_DATA), flags, and callout IDs. Network rootkits register WFP callouts to intercept traffic invisibly below netstat.',
    {},
    async () => {
      const result = await httpClient.post('/api/wfp/enumerate_callouts', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_wfp_validate_callout_pointers',
    'Validate WFP callout function pointers (classifyFn, notifyFn, flowDeleteFn) against known benign provider GUIDs and signed kernel driver modules. Returns layer risk matrix, suspicious indicator patterns, and known rootkit examples (Azazel, ZeroAccess, TDL4) using WFP for C2 hiding.',
    {},
    async () => {
      const result = await httpClient.post('/api/wfp/validate_callout_pointers', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_wfp_detect_hidden_callouts',
    'Detect hidden WFP callouts registered via FwpsCalloutRegister but absent from FwpmCalloutEnum0 (BFE database). Returns four detection techniques: kernel FWPS table inspection, ETW Threat Intelligence monitoring, filter-vs-callout ID cross-reference, and netio.sys heap scanning approach.',
    {},
    async () => {
      const result = await httpClient.post('/api/wfp/detect_hidden_callouts', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );
}
