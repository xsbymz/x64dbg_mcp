import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerSideChannelAnalyzerTools(server: McpServer) {
  server.tool('x64dbg_sc_detect_spectre_gadgets', 'Detect Spectre/Meltdown gadgets: indirect branch predictors, RSB underflow, cache timing.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/detect_spectre_gadgets', {}), null, 2) }] };
  });
  server.tool('x64dbg_sc_analyze_branch_predictor', 'Analyze branch predictor state and detect BTB/RSB/RAS manipulation for speculative execution attacks.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/analyze_branch_predictor', {}), null, 2) }] };
  });
  server.tool('x64dbg_sc_detect_cache_timing', 'Detect cache timing side-channels: Flush+Reload, Prime+Probe, Evict+Reload patterns.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/detect_cache_timing', {}), null, 2) }] };
  });
  server.tool('x64dbg_sc_detect_rdtsc_abuse', 'Detect RDTSC/RDTSCP instruction abuse for timing side-channels and covert channels.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/detect_rdtsc_abuse', {}), null, 2) }] };
  });
  server.tool('x64dbg_sc_analyze_transient_exec', 'Analyze transient execution windows: Spectre v1/v2/v3/v4/v5/v6 attack surfaces.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/analyze_transient_exec', {}), null, 2) }] };
  });
  server.tool('x64dbg_sc_detect_rowhammer', 'Detect Rowhammer attack patterns: CLFLUSH/CLFLUSHOPT loops, double-sided hammering.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/detect_rowhammer', {}), null, 2) }] };
  });
  server.tool('x64dbg_sc_analyze_microarchitectural', 'Analyze microarchitectural state: cache hierarchy, TLB, branch predictor, ROB state.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/analyze_microarchitectural', {}), null, 2) }] };
  });
  server.tool('x64dbg_sc_detect_l1tf', 'Detect L1 Terminal Fault (Foreshadow) attack patterns and SMEP bypass vectors.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/detect_l1tf', {}), null, 2) }] };
  });
  server.tool('x64dbg_sc_analyze_mds', 'Analyze Microarchitectural Data Sampling (MDS) vulnerabilities: RIDL, ZombieLoad, Fallout.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/analyze_mds', {}), null, 2) }] };
  });
  server.tool('x64dbg_sc_detect_inclusive_cache_abuse', 'Detect inclusive cache abuse for cross-core data exfiltration via cache eviction.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/detect_inclusive_cache_abuse', {}), null, 2) }] };
  });
  server.tool('x64dbg_sc_measure_cache_contention', 'Measure cache contention and detect covert channel communication patterns.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/measure_cache_contention', {}), null, 2) }] };
  });
  server.tool('x64dbg_sc_detect_smt_abuse', 'Detect Simultaneous Multithreading (SMT/Hyper-Threading) abuse for cross-thread data leakage.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/side_channel/detect_smt_abuse', {}), null, 2) }] };
  });
}
