import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerKrnlPciDmaAuditorTools(server: McpServer) {
  server.tool(
    'x64dbg_krnl_pci_dma_auditor',
    'Kernel PCI/PCIe configuration space, IOMMU DMA protection domains, and ATS capability auditor.',
    {
      action: z.discriminatedUnion('action', [
        z.object({
          action: z.literal('audit_dma_domains')
        }),
        z.object({
          action: z.literal('scan_pcie_capabilities')
        })
      ])
    },
    async ({ action }) => {
      try {
        let data: unknown;
        switch (action.action) {
          case 'audit_dma_domains':
            data = await httpClient.post('/api/pci_dma/audit_dma_domains', {});
            break;
          case 'scan_pcie_capabilities':
            data = await httpClient.post('/api/pci_dma/scan_pcie_capabilities', {});
            break;
        }
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true };
      }
    }
  );
}
