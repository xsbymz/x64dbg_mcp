import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerGolangAdvancedAnalysisTools(server: McpServer) {
  server.tool('x64dbg_go_extract_interface_itab', 'Extract Go interface itab (interface table) structures and reconstruct interface-to-type mappings.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/extract_interface_itab', {}), null, 2) }] };
  });
  server.tool('x64dbg_go_reconstruct_goid_scheduler', 'Reconstruct Go goroutine (G) scheduler state: P, M, G structures, runqueue, status flags.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/reconstruct_goid_scheduler', {}), null, 2) }] };
  });
  server.tool('x64dbg_go_extract_string_keys', 'Extract Go string keys from map structures (runtime/map) using hash table walking.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/extract_string_keys', {}), null, 2) }] };
  });
  server.tool('x64dbg_go_analyze_go_interface', 'Analyze Go interface{} and any conversions: eface, iface, type assertions.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/analyze_go_interface', {}), null, 2) }] };
  });
  server.tool('x64dbg_go_detect_channel_operations', 'Detect Go channel (hchan) operations and reconstruct send/receive patterns.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/detect_channel_operations', {}), null, 2) }] };
  });
  server.tool('x64dbg_go_analyze_goroutine_stack', 'Analyze goroutine stack layout: g0, g signal stack, stack bounds, decrementing stack.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/analyze_goroutine_stack', {}), null, 2) }] };
  });
  server.tool('x64dbg_go_detect_reflect_abuse', 'Detect reflect package abuse for dynamic method invocation and type confusion.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/detect_reflect_abuse', {}), null, 2) }] };
  });
  server.tool('x64dbg_go_extract_build_info', 'Extract Go build info: module path, version, VCS revision, toolchain version.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/extract_build_info', {}), null, 2) }] };
  });
  server.tool('x64dbg_go_analyze_go_versions', 'Analyze Go version-specific runtime differences and ABI changes.', { version: z.string().optional() }, async ({ version }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/analyze_go_versions', { version: version ?? '1.21' }), null, 2) }] };
  });
  server.tool('x64dbg_go_detect_cgo_boundaries', 'Detect cgo boundaries and C/Go interop patterns for cross-language vulnerability analysis.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/detect_cgo_boundaries', {}), null, 2) }] };
  });
  server.tool('x64dbg_go_reconstruct_type_descriptors', 'Reconstruct Go type descriptors (_type, uncommonType, structType, sliceType, mapType).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/reconstruct_type_descriptors', {}), null, 2) }] };
  });
  server.tool('x64dbg_go_detect_race_detector', 'Detect Go race detector instrumentation and extract race report data.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/golang/detect_race_detector', {}), null, 2) }] };
  });
}
