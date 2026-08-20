import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerRustAdvancedAnalysisTools(server: McpServer) {
  server.tool('x64dbg_rust_extract_heap_strings', 'Extract heap-allocated strings from Rust binaries (inlined as immediate operands, not in .rdata).', { module_name: z.string().optional() }, async ({ module_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/extract_heap_strings', { module_name: module_name ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_rust_demangle_symbols', 'Demangle Rust symbol names with full path reconstruction (generic instantiation, trait resolution).', { mangled: z.string().describe('Mangled Rust symbol') }, async ({ mangled }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/demangle_symbols', { mangled }), null, 2) }] };
  });
  server.tool('x64dbg_rust_analyze_monomorphization', 'Analyze generic monomorphization patterns and reconstruct template instantiation map.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/analyze_monomorphization', {}), null, 2) }] };
  });
  server.tool('x64dbg_rust_detect_inlined_library', 'Detect deeply inlined library code (up to 5 levels) using call graph and basic block analysis.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/detect_inlined_library', {}), null, 2) }] };
  });
  server.tool('x64dbg_rust_extract_panic_payload', 'Extract panic payloads and backtrace information from Rust binaries.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/extract_panic_payload', {}), null, 2) }] };
  });
  server.tool('x64dbg_rust_detect_unsafe_blocks', 'Detect unsafe code blocks and FFI boundaries in Rust binaries.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/detect_unsafe_blocks', {}), null, 2) }] };
  });
  server.tool('x64dbg_rust_analyze_trait_objects', 'Analyze trait object vtables and dynamic dispatch patterns (dyn Trait, Box<dyn FnOnce>).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/analyze_trait_objects', {}), null, 2) }] };
  });
  server.tool('x64dbg_rust_detect_obfstr_encoding', 'Detect obfstr crate string obfuscation and extract compile-time encrypted strings.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/detect_obfstr_encoding', {}), null, 2) }] };
  });
  server.tool('x64dbg_rust_reconstruct_smart_ptrs', 'Reconstruct Box, Rc, Arc, and Cow smart pointer usage patterns from memory layout.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/reconstruct_smart_ptrs', {}), null, 2) }] };
  });
  server.tool('x64dbg_rust_analyze_allocators', 'Analyze custom allocator usage: GlobalAlloc, System, mimalloc, jemalloc patterns.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/analyze_allocators', {}), null, 2) }] };
  });
  server.tool('x64dbg_rust_detect_borrow_violations', 'Detect potential borrow checker violations in compiled binaries (unsafe transmute, lifetime扩展).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/detect_borrow_violations', {}), null, 2) }] };
  });
  server.tool('x64dbg_rust_analyze_async_runtime', 'Analyze async runtime: tokio/epoll, task spawning, waker patterns, future state machines.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/rust/analyze_async_runtime', {}), null, 2) }] };
  });
}
