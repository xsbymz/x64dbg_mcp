#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_spi_flash_routes(c_http_router& router) {
    router.post("/api/spi/read_descriptor_map", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["spi_descriptor_layout"] = {
            {"FD_Signature","0x0FF0A55A at offset 0x10 — Flash Descriptor Valid Magic"},
            {"Region_0","Flash Descriptor (4KB) — contains access permissions table"},
            {"Region_1","BIOS / UEFI (holds DXE, PEI volumes, Microcode, NVRAM)"},
            {"Region_2","Intel ME / CSME (Management Engine firmware)"},
            {"Region_3","GbE (Gigabit Ethernet MAC & configuration)"},
            {"Region_4","PDR (Platform Data Region)"},
            {"Region_5","Device Expansion / EC (Embedded Controller)"}
        };
        result["master_access_permissions"] = {
            {"BIOS_Master","Host CPU running BIOS — read/write rights to BIOS region"},
            {"ME_Master","Intel ME controller — read/write rights across ME and sometimes BIOS"},
            {"GbE_Master","Ethernet controller — GbE region access"}
        };
        result["threat_intelligence"] = {
            "CosmicStrand & MoonBounce: persistent implants in SPI flash BIOS region",
            "Flash Protection Override: HDA_SDO jumper / pin strap overrides descriptor security"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/spi/get_region_access_rights", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["pr_registers"] = {
            {"PR0-PR4","Protected Range Registers in Intel SPI Controller (RCBA/MMIO base 0xFE010000 / SPIBAR)"},
            {"PR_Bit_31","Write Protection Enable (WPE)"},
            {"PR_Bit_15","Read Protection Enable (RPE)"},
            {"SMM_BWP","SMM BIOS Write Protect bit in BIOS_CNTL register"}
        };
        result["vulnerability_vectors"] = {
            "SMM_BWP=0: Ring-0 code can write directly to SPI flash without SMM mediation",
            "BIOS_WE=1 (BIOS Write Enable): Flash is unlocked for write cycles",
            "BLE=0 (BIOS Lock Enable): BIOS_CNTL can be toggled without triggering SMI"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/spi/detect_region_anomalies", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["anomaly_detection_rules"] = {
            "1. Check if SMM_BWP (BIOS_CNTL bit 5) is disabled — allows non-SMM SPI flash overwrite",
            "2. Check if BIOS_LOCK (BLE bit 1) is cleared — allows arbitrary BIOS_WE toggling",
            "3. Verify Flash Descriptor Security Override Strap (HDA_SDO loop) is not asserting unrestricted mode",
            "4. Compare BIOS region cryptographic hash against OEM golden image"
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
