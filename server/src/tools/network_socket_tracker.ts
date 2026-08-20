import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerNetworkSocketTrackerTools(server: McpServer) {
  server.tool(
    'x64dbg_network_socket_tracker',
    'Track and inspect network sockets created by debuggee: list TCP/UDP sockets, remote IP/port endpoints, TLS handshakes, and dump active I/O communication buffers.',
    {
      action: z.enum(['list_active_sockets', 'dump_socket_buffers', 'get_connection_history', 'inspect_dns_queries']).describe('Socket tracking action'),
    },
    async ({ action }) => {
      let data: unknown;
      switch (action) {
        case 'list_active_sockets':
          data = await httpClient.get('/api/socket/active');
          break;
        case 'dump_socket_buffers':
          data = await httpClient.get('/api/socket/buffers');
          break;
        case 'get_connection_history':
          data = await httpClient.get('/api/socket/history');
          break;
        case 'inspect_dns_queries':
          data = await httpClient.get('/api/socket/dns_queries');
          break;
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
