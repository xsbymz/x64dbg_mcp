import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerCloudNativeAnalyzerTools(server: McpServer) {
  server.tool('x64dbg_cn_detect_container_escape', 'Detect container escape techniques: namespace breakout, cgroup escape, procfs manipulation.', { pid: z.number().optional() }, async ({ pid }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cloud_native/detect_container_escape', { pid: pid ?? 0 }), null, 2) }] };
  });
  server.tool('x64dbg_cn_analyze_docker_breakout', 'Analyze Docker container breakout vectors: privileged mode, mount namespace, /proc access.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cloud_native/analyze_docker_breakout', {}), null, 2) }] };
  });
  server.tool('x64dbg_cn_detect_k8s_attack_surface', 'Detect Kubernetes attack surface: kubelet API, service account tokens, RBAC misconfigurations.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cloud_native/detect_k8s_attack_surface', {}), null, 2) }] };
  });
  server.tool('x64dbg_cn_analyze_wsl2_pico', 'Analyze WSL2 Pico process security: LxCore.sys, VFS, Linux syscall emulation, LxssManager.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cloud_native/analyze_wsl2_pico', {}), null, 2) }] };
  });
  server.tool('x64dbg_cn_detect_ebpf_malware', 'Detect eBPF-based malware: malicious eBPF programs, JIT code injection, kernel access abuse.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cloud_native/detect_ebpf_malware', {}), null, 2) }] };
  });
  server.tool('x64dbg_cn_analyze_service_mesh', 'Analyze service mesh sidecar patterns: Envoy, Istio, Linkerd proxy injection.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cloud_native/analyze_service_mesh', {}), null, 2) }] };
  });
  server.tool('x64dbg_cn_detect_supply_chain_attack', 'Detect software supply chain attacks: compromised packages, build pipeline injection, dependency confusion.', { package_path: z.string().optional() }, async ({ package_path }) => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cloud_native/detect_supply_chain_attack', { package_path: package_path ?? '' }), null, 2) }] };
  });
  server.tool('x64dbg_cn_analyze_serverless_runtime', 'Analyze serverless runtime security: FaaS cold start, function injection, event trigger manipulation.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cloud_native/analyze_serverless_runtime', {}), null, 2) }] };
  });
  server.tool('x64dbg_cn_detect_crypto_miner', 'Detect cryptocurrency miner patterns: XMRig, RandomX, CryptoNight, memory allocation patterns.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cloud_native/detect_crypto_miner', {}), null, 2) }] };
  });
  server.tool('x64dbg_cn_analyze_oci_runtime', 'Analyze OCI container runtime (runc, crun) for CVE exploitation and escape vectors.', {}, async () => {
    return { content: [{ type: 'text', text: JSON.stringify(await httpClient.post('/api/cloud_native/analyze_oci_runtime', {}), null, 2) }] };
  });
}
