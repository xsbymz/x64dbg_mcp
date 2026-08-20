#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_loldrivers_scanner_routes(c_http_router& router) {
    router.post("/api/loldriver/scan_loaded_drivers", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["byovd_attack_concept"] = {
            "Bring Your Own Vulnerable Driver (BYOVD) drops a legitimate, Microsoft-signed driver containing known kernel Read/Write primitives",
            "Adversary loads the signed driver to bypass Driver Signature Enforcement (DSE)",
            "Exploits IOCTLs to disable EDR kernel callbacks, clear CI!g_CiOptions, or terminate protected processes (PPL)"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/loldriver/match_against_known_vulnerable", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["notable_vulnerable_drivers"] = {
            {"RTCore64.sys", "Micro-Star MSI Afterburner driver — CVE-2019-16098 (Arbitrary kernel R/W via IOCTL 0x80002048)"},
            {"gdrv.sys", "GIGABYTE driver — CVE-2018-19320 (Arbitrary physical memory mapping and kernel R/W)"},
            {"iqvw64e.sys", "Intel Network Adapter Diagnostic Driver — arbitrary kernel memory write"},
            {"dbutil_2_3.sys", "Dell BIOS Utility driver — CVE-2021-21551"},
            {"procexp.sys", "Legacy Process Explorer driver with unchecked handle duplication IOCTL"},
            {"mhyprot2.sys", "Genshin Impact anti-cheat driver abused by ransomware to kill antivirus processes"}
        };
        result["database_reference"] = "https://www.loldrivers.io/ API matching based on SHA256 / Authenticode signer certificate";
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/loldriver/assess_byovd_risk", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["mitigation_status"] = {
            {"Driver_Blocklist", "Microsoft Vulnerable Driver Blocklist (HVCI enabled by default in Windows 11)"},
            {"WDAC_Policy", "Windows Defender Application Control policy enforcing driver hash blacklisting"}
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
