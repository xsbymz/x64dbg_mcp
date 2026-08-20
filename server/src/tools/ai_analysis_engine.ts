import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAiAnalysisEngineTools(server: McpServer) {
  server.tool('x64dbg_ai_detect_compiler_embedding', 'Use ML embeddings to identify compiler toolchain from binary features (MSVC, GCC, Clang, Rust, Go, Delphi).', { module_name: z.string().optional() }, async ({ module_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ai/detect_compiler_embedding', { module_name: module_name ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_ai_classify_malware_family', 'Classify malware family using code similarity embeddings and behavioral patterns.', { sample_path: z.string().describe('Path to malware sample') }, async ({ sample_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ai/classify_malware_family', { sample_path }), null, 2) }] };
  });
  server.tool('x64dbg_ai_generate_yara_from_features', 'Generate YARA rules automatically from binary features using ML-based pattern extraction.', { features: z.array(z.string()).optional() }, async ({ features }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ai/generate_yara_from_features', { features: features ?? [] }), null, 2) }] };
  });
  server.tool('x64dbg_ai_detect_vulnerability_patterns', 'Detect vulnerability patterns using ML models trained on CVE datasets.', { module_name: z.string().optional() }, async ({ module_name }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ai/detect_vulnerability_patterns', { module_name: module_name ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_ai_suggest_decompilation_hints', 'Generate AI-suggested decompilation hints for complex functions.', { function_address: z.string().describe('Function address hex') }, async ({ function_address }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ai/suggest_decompilation_hints', { function_address }), null, 2) }] };
  });
  server.tool('x64dbg_ai_detect_obfuscation_techniques', 'Detect obfuscation techniques using ML classification (control flow flattening, opaque predicates, packing).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ai/detect_obfuscation_techniques', {}), null, 2) }] };
  });
  server.tool('x64dbg_ai_cluster_similar_functions', 'Cluster similar functions across binaries using embedding similarity.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ai/cluster_similar_functions', {}), null, 2) }] };
  });
  server.tool('x64dbg_ai_detect_supply_chain_risk', 'Detect supply chain risk indicators using ML on dependency graphs and metadata.', { module_path: z.string().optional() }, async ({ module_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ai/detect_supply_chain_risk', { module_path: module_path ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_ai_predict_exploitability', 'Predict exploitability score using ML on crash telemetry and binary features.', { crash_dump_path: z.string().describe('Path to crash dump') }, async ({ crash_dump_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ai/predict_exploitability', { crash_dump_path }), null, 2) }] };
  });
  server.tool('x64dbg_ai_extract_meaningful_strings', 'Extract meaningful strings using NLP models (filter noise, classify language, detect secrets).', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/ai/extract_meaningful_strings', {}), null, 2) }] };
  });
}
