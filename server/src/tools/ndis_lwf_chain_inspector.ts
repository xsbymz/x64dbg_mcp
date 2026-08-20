import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { httpClient } from '../http_client.js';

export function registerNdisLwfChainInspectorTools(server: McpServer) {
  server.tool(
    'x64dbg_ndis_lwf_enumerate_filters',
    'Enumerate NDIS LightWeight Filter (LWF) chain on all network adapters. Returns adapter descriptions, NetCfgInstanceId GUIDs, and bound filter driver lists. NDIS rootkits (TDL4, Necurs, Azazel) insert phantom LWF modules below the TCP/IP stack to intercept raw frames invisible to netstat, WFP, and Wireshark.',
    {},
    async () => {
      const result = await httpClient.post('/api/ndis_lwf/enumerate_filters', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_ndis_lwf_validate_dispatch_pointers',
    'Validate NDIS LWF dispatch handler function pointers (FilterReceiveNetBufferLists, FilterSendNetBufferLists, FilterAttach, FilterOidRequest, etc.) against loaded signed kernel drivers. Returns 5-step kernel _NDIS_FILTER_BLOCK inspection methodology and shadow filter detection indicators.',
    {},
    async () => {
      const result = await httpClient.post('/api/ndis_lwf/validate_dispatch_pointers', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_ndis_lwf_detect_shadow_filters',
    'Detect shadow NDIS LWF filter modules not appearing in standard adapter enumeration. Returns 4 detection approaches: ndis!ndisGlobalFilterDriverList walk, adapter FilterList chain analysis, registry vs kernel comparison, and NdisPacketCapture ETW monitoring. Identifies packet hiding, dropping, and C2 exfiltration via NBL cloning.',
    {},
    async () => {
      const result = await httpClient.post('/api/ndis_lwf/detect_shadow_filters', {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );
}
