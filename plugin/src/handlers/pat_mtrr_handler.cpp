#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <intrin.h>
using json = nlohmann::json;

namespace handlers {
void register_pat_mtrr_routes(c_http_router& router) {
    router.post("/api/mtrr/read_all", [](const s_http_request& req) {
        json result;
        int info[4]={};
        __cpuid(info,1);
        bool mtrrSupported = (info[3]>>12)&1;
        result["mtrr_supported"] = mtrrSupported;
        result["mtrr_reference"] = {
            {"IA32_MTRRCAP","0xFE — number of variable MTRRs, fixed-range support, WC support"},
            {"IA32_MTRR_DEF_TYPE","0x2FF — default memory type when no MTRR matches"},
            {"IA32_MTRR_PHYSBASEn","0x200+2n — physical base of variable MTRR n"},
            {"IA32_MTRR_PHYSMASKn","0x201+2n — physical mask and valid bit of variable MTRR n"}
        };
        result["memory_types"] = {
            {{"type",0},{"name","UC — Uncacheable"},{"note","Disables all caching including write-combining"}},
            {{"type",1},{"name","WC — Write-Combining"},{"note","Writes combined in buffer, order not guaranteed"}},
            {{"type",4},{"name","WT — Write-Through"},{"note","Reads cached, writes go to memory and cache"}},
            {{"type",5},{"name","WP — Write-Protected"},{"note","Reads cached, writes cause bus cycle and invalidate"}},
            {{"type",6},{"name","WB — Write-Back"},{"note","Fully cached with write-back; default for RAM"}}
        };
        result["rootkit_abuse"] = {
            "Make MTRR region UC (type=0) to prevent cache-based timing analysis from detecting rootkit presence",
            "Map physical MMIO regions as WC for fast DMA-style memory access without going through OS",
            "Fingerprinting: UC regions in unexpected physical ranges = potential rootkit MMIO mapping"
        };
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/mtrr/detect_suspicious_uc_regions", [](const s_http_request& req) {
        json result;
        result["suspicious_uc_patterns"] = {
            "UC regions covering RAM (not MMIO) ranges suggest rootkit disabling cache for stealth",
            "WC regions in address ranges >4GB physical that are not PCI BARs",
            "Regions overlapping known legitimate MMIO (0xA0000-0xBFFFF VGA, 0xE0000-0xEFFFF firmware)"
        };
        result["legitimate_uc_regions"] = {
            {"0x00000000A0000-0x0000000BFFFF","VGA frame buffer"},
            {"0x00000000C0000-0x0000000DFFFF","Video BIOS"},
            {"0x00000000E0000-0x0000000FFFFF","BIOS ROM"},
            {"PCIe_BARs","PCI Base Address Registers — device MMIO, varies by hardware"}
        };
        result["detection_approach"] = "Read IA32_MTRRCAP (count), then IA32_MTRR_PHYSBASEn (base+type) and IA32_MTRR_PHYSMASKn (mask+valid) for each variable MTRR. Identify type=0 (UC) regions covering non-MMIO physical RAM.";
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/pat/read_entry_table", [](const s_http_request& req) {
        json result;
        result["pat_msr"] = "0x277 (IA32_PAT) — 8 entries, 3 bits each, maps PTE.PAT/PCD/PWT bits to memory type";
        result["default_pat"] = {
            {"PA0_bits_000","WB — Write-Back (default)"},
            {"PA1_bits_001","WT — Write-Through"},
            {"PA2_bits_010","UC- — Uncacheable Minus (WC if MTRR=WC)"},
            {"PA3_bits_011","UC — Uncacheable"},
            {"PA4_bits_100","WB — Write-Back"},
            {"PA5_bits_101","WT — Write-Through"},
            {"PA6_bits_110","UC-"},
            {"PA7_bits_111","UC"}
        };
        result["exploit_relevance"] = {
            "PAT entry 7 (bits 111) = UC: attacker changes PAT to map physical address as executable WC/WB for shellcode placement",
            "JIT engines set PTE.PWT/PCD for WRITE+EXECUTE: PAT manipulation can make JIT pages different cacheability",
            "Hypervisor attack: modify EPT PAT-like bits to change guest page cacheability without guest knowing"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

