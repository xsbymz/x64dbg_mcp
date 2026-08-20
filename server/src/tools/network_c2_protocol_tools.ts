import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerNetworkC2ProtocolTools(server: McpServer) {
  // Cobalt Strike Beacon
  server.tool('x64dbg_cs_beacon_scan_memory', 'Scan process memory for Cobalt Strike Beacon configuration blocks.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cs_beacon/scan_memory', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_cs_beacon_extract_config', 'Extract and decode Cobalt Strike Malleable C2 parameters.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cs_beacon/extract_config', {}), null, 2) }] };
  });
  server.tool('x64dbg_cs_beacon_detect_sleep_obf', 'Detect sleep obfuscation memory state transitions in beacon processes.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cs_beacon/detect_sleep_obfuscation', { pid: pid ?? 0 }), null, 2) }] };
  });

  // Named Pipe C2
  server.tool('x64dbg_pipe_c2_enumerate', 'Enumerate all active named pipes on \\\\.\\pipe\\.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/pipe_c2/enumerate_all_pipes', {}), null, 2) }] };
  });
  server.tool('x64dbg_pipe_c2_match_patterns', 'Match named pipes against known C2 profiles (CS, Metasploit, Sliver, Havoc).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/pipe_c2/match_known_c2_patterns', {}), null, 2) }] };
  });
  server.tool('x64dbg_pipe_c2_analyze_connections', 'Analyze client/server process security contexts and DACL on a named pipe.', { pipe_name: z.string().describe('Pipe name') }, async ({ pipe_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/pipe_c2/analyze_pipe_connections', { pipe_name }), null, 2) }] };
  });

  // DNS-over-HTTPS (DoH)
  server.tool('x64dbg_doh_detect_connections', 'Detect active socket connections to known public DoH resolvers.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/doh/detect_active_connections', {}), null, 2) }] };
  });
  server.tool('x64dbg_doh_scan_memory', 'Scan process memory for embedded DoH resolver URLs and query strings.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/doh/scan_memory_for_doh_ips', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_doh_correlate_bypasses', 'Correlate DNS resolution bypasses and hosts file tampering.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/doh/correlate_resolver_bypasses', {}), null, 2) }] };
  });

  // Raw Sockets & ICMP C2
  server.tool('x64dbg_raw_socket_enumerate', 'Enumerate raw sockets (SOCK_RAW) across all process handles.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/raw_socket/enumerate_raw_sockets', {}), null, 2) }] };
  });
  server.tool('x64dbg_raw_socket_detect_icmp_tunnel', 'Detect ICMP Echo data payload tunneling and entropy anomalies.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/raw_socket/detect_icmp_tunneling_patterns', {}), null, 2) }] };
  });
  server.tool('x64dbg_raw_socket_correlate_activity', 'Correlate raw socket handle creation with process token privileges.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/raw_socket/correlate_with_network_activity', {}), null, 2) }] };
  });

  // HTTP/2 & Protobuf C2
  server.tool('x64dbg_http2_scan_frames', 'Scan process memory for HTTP/2 client prefaces and binary frames.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/http2/scan_memory_for_frames', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_http2_decode_stream', 'Decode HTTP/2 frame stream (HEADERS, DATA, SETTINGS, PING).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/http2/decode_frame_stream', {}), null, 2) }] };
  });
  server.tool('x64dbg_http2_extract_c2_indicators', 'Extract C2 indicators from HTTP/2 multiplexed streams.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/http2/extract_c2_indicators', {}), null, 2) }] };
  });

  server.tool('x64dbg_protobuf_scan_memory', 'Scan process memory for Protocol Buffers binary wire format payloads.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/protobuf/scan_memory', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_protobuf_decode_wire', 'Decode Protocol Buffers wire format (Varint, 64-bit, Length-delimited).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/protobuf/decode_wire_format', {}), null, 2) }] };
  });
  server.tool('x64dbg_protobuf_detect_grpc_c2', 'Detect gRPC-based C2 communication headers and payload structures.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/protobuf/detect_grpc_c2', {}), null, 2) }] };
  });
}
