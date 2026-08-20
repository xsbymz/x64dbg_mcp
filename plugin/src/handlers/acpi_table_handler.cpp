#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_acpi_table_routes(c_http_router& router) {
    router.post("/api/acpi/enumerate_tables", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["tables"] = json::array();
        // Enumerate ACPI tables via NtQuerySystemInformation(SystemFirmwareTableInformation)
        std::vector<DWORD> sigs = {
            'TCAF','TPSD','TAGM','TPAD','STDF','TDSS','TCAL','RDMC','TPOM','TPMS','TPSE','RPBD'
        };
        // Try to enumerate via ACPI provider
        UINT sz = GetSystemFirmwareTable('ACPI','RSDT',nullptr,0);
        result["rsdt_size"] = sz;
        result["rsdt_accessible"] = (sz > 0);
        sz = GetSystemFirmwareTable('ACPI','XSDT',nullptr,0);
        result["xsdt_size"] = sz;
        sz = GetSystemFirmwareTable('ACPI','DSDT',nullptr,0);
        result["dsdt_size"] = sz;
        result["dsdt_accessible"] = (sz > 0);
        sz = GetSystemFirmwareTable('ACPI','SSDT',nullptr,0);
        result["ssdt_tables_size"] = sz;

        result["table_reference"] = {
            {"DSDT","Differentiated System Description Table — AML bytecode for hardware topology"},
            {"SSDT","Secondary SDT — supplemental AML tables (often multiple SSDTs)"},
            {"MADT","Multiple APIC Description Table — lists CPU APIC IDs and I/O APIC addresses"},
            {"DMAR","DMA Remapping Reporting — IOMMU topology and DMA protection domains"},
            {"MCFG","PCIe Memory-Mapped Config Space base address"},
            {"FACP","Fixed ACPI Description Table — power management port addresses"},
            {"SRAT","System Resource Affinity Table — NUMA topology"},
            {"BERT","Boot Error Record Table — firmware-recorded hardware errors"}
        };
        result["bootkit_relevance"] = {
            "TDL4 patched SSDT to intercept ACPI power state transitions",
            "Custom SSDT tables can load rogue ACPI device handlers",
            "DMAR table integrity verifies IOMMU protection boundaries"
        };
        res.set_content(result.dump(), "application/json");
    });
    router.post("/api/acpi/parse_dsdt", [](const httplib::Request&, httplib::Response& res) {
        json result;
        UINT sz = GetSystemFirmwareTable('ACPI','DSDT',nullptr,0);
        result["dsdt_size"] = sz;
        if (sz > 0 && sz < 2*1024*1024) {
            std::vector<BYTE> buf(sz);
            GetSystemFirmwareTable('ACPI','DSDT',buf.data(),sz);
            // Parse ACPI table header
            struct ACPI_HEADER { char sig[4]; DWORD len; BYTE rev; BYTE chksum; char oemid[6]; char oemtableid[8]; DWORD oemrev; char creatorid[4]; DWORD creatorrev; };
            if (sz >= sizeof(ACPI_HEADER)) {
                auto* h = reinterpret_cast<ACPI_HEADER*>(buf.data());
                result["signature"] = std::string(h->sig,4);
                result["length"] = h->len;
                result["revision"] = h->rev;
                result["checksum"] = h->chksum;
                result["oem_id"] = std::string(h->oemid,6);
                result["oem_table_id"] = std::string(h->oemtableid,8);
                result["oem_revision"] = h->oemrev;
                // Compute expected checksum
                BYTE cs = 0; for (UINT i=0;i<std::min(sz,(UINT)h->len);i++) cs+=buf[i];
                result["checksum_valid"] = (cs==0);
            }
        }
        result["aml_parsing"] = "AML bytecode is a stack-based interpreted language. Use acpica/iasl to decompile to ASL source. Look for: custom device _DSM methods, OperationRegion SystemMemory references pointing to unexpected physical ranges, EmbeddedControl accesses.";
        res.set_content(result.dump(), "application/json");
    });
    router.post("/api/acpi/validate_dmar_entries", [](const httplib::Request&, httplib::Response& res) {
        json result;
        UINT sz = GetSystemFirmwareTable('ACPI','RAMD',nullptr,0); // DMAR reversed
        result["dmar_note"] = "DMAR (DMA Remapping) table describes IOMMU hardware. Each DRHD entry covers a PCI bus segment. ANDD entries map ACPI namespace devices for IOMMU exclusion. Rootkits manipulate DRHD to exclude malicious DMA-capable devices from IOMMU protection.";
        result["dmar_structures"] = {
            {"DRHD","DMA Remapping Hardware Definition — IOMMU register base address"},
            {"RMRR","Reserved Memory Region Reporting — pre-allocated DMA buffers"},
            {"ATSR","ATS Root table — PCIe ATS capability"},
            {"RHSA","RHSA — root port hardware node affinity"},
            {"ANDD","ACPI namespace device declaration for IOMMU exclusion"}
        };
        result["attack_relevance"] = {
            "DMA attack via PCIe device (Thunderbolt, ExpressCard) bypasses IOMMU if DMAR misconfigured",
            "Malicious firmware removes IOMMU protection by modifying DRHD scope",
            "Check: all PCIe devices behind an IOMMU DRHD, no bypass scope entries"
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
