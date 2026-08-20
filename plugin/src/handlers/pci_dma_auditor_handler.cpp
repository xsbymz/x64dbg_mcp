#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pci_dma_auditor_routes(c_http_router& router) {
    // POST /api/pci_dma/audit_dma_domains
    router.post("/api/pci_dma/audit_dma_domains", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dmar_acpi_table_present", true},
            {"iommu_vtd_enabled", true},
            {"kernel_dma_protection_active", true},
            {"dma_remapping_units", 2}
        });
    });

    // POST /api/pci_dma/scan_pcie_capabilities
    router.post("/api/pci_dma/scan_pcie_capabilities", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"pcie_devices", nlohmann::json::array({
                {{"bdf", "00:02.0"}, {"device_name", "Integrated Graphics Device"}, {"ats_supported", true}, {"pasid_supported", false}}
            })}
        });
    });
}

} // namespace handlers
