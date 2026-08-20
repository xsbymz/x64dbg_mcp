function parseTimeout(raw: string | undefined): number {
  // Debugger operations (run, trace, step-over-call) are unbounded by nature,
  // so the default is "no timeout" (0) to match talking to the plugin with curl,
  // which has no default timeout. Users who want a hard ceiling can set
  // X64DBG_MCP_TIMEOUT to a positive millisecond value. 0 or negative = wait forever.
  if (raw !== undefined && raw !== '') {
    const value = parseInt(raw, 10);
    if (Number.isNaN(value)) {
      // Warn rather than silently ignoring the misconfiguration
      console.error(
        `[x64dbg-mcp] WARNING: X64DBG_MCP_TIMEOUT="${raw}" is not a valid number; ` +
        `defaulting to no timeout (0). Set it to a positive integer (milliseconds).`
      );
      return 0;
    }
    return value <= 0 ? 0 : value;
  }
  return 0;
}

function parseIntEnv(raw: string | undefined, varName: string, defaultValue: number): number {
  if (raw === undefined || raw === '') return defaultValue;
  const value = parseInt(raw, 10);
  if (Number.isNaN(value)) {
    console.error(
      `[x64dbg-mcp] WARNING: ${varName}="${raw}" is not a valid integer; ` +
      `using default value ${defaultValue}.`
    );
    return defaultValue;
  }
  return value;
}

function parseBoolEnv(raw: string | undefined, defaultValue: boolean): boolean {
  if (raw === undefined || raw === '') return defaultValue;
  const lower = raw.toLowerCase().trim();
  return lower === 'true' || lower === '1' || lower === 'yes';
}

export const config = {
  host: process.env.X64DBG_MCP_HOST ?? '127.0.0.1',
  port: parseIntEnv(process.env.X64DBG_MCP_PORT, 'X64DBG_MCP_PORT', 27042),
  // 0 = no timeout (wait indefinitely). See parseTimeout above.
  timeout: parseTimeout(process.env.X64DBG_MCP_TIMEOUT),
  retries: parseIntEnv(process.env.X64DBG_MCP_RETRIES, 'X64DBG_MCP_RETRIES', 3),
  // Optional auth token. When set, it must match the plugin's configured token
  // (Settings > Token). Sent as "Authorization: Bearer <token>". Empty = no auth.
  token: process.env.X64DBG_MCP_TOKEN ?? '',
  // Read-only safety mode: blocks destructive mutations (memory write, patches, bp delete)
  readOnly: parseBoolEnv(process.env.X64DBG_MCP_READONLY, false),
  // Maximum payload size in megabytes for large responses
  maxPayloadMb: parseIntEnv(process.env.X64DBG_MCP_MAX_PAYLOAD_MB, 'X64DBG_MCP_MAX_PAYLOAD_MB', 64),
  // Logging verbosity level: 'debug' | 'info' | 'warn' | 'error'
  logLevel: (process.env.X64DBG_MCP_LOG_LEVEL ?? 'info').toLowerCase(),
  // Anti-CSRF Origin check enforcement toggle
  originCheck: parseBoolEnv(process.env.X64DBG_MCP_ORIGIN_CHECK, true),
};

export function getBaseUrl(): string {
  return `http://${config.host}:${config.port}`;
}

