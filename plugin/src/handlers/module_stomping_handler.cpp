#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_module_stomping_routes(c_http_router& router) {
    router.post("/api/module_stomp/scan_loaded_modules", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["module_stomping_concept"] = {
            "1. Attacker loads a legitimate, signed DLL (e.g. via LoadLibraryA)",
            "2. Modifies memory protection of .text / executable section with VirtualProtect",
            "3. Overwrites (stomps) the executable section with payload shellcode",
            "4. Module remains listed in PEB.InLoadOrderModuleList with valid on-disk file path and Authenticode metadata",
            "5. Bypasses naive memory scanners that only check if RIP is within a loaded module's address range"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/module_stomp/compare_disk_vs_memory", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string moduleName = body.value("module_name", "");
        json result;
        result["module_name"] = moduleName;
        result["comparison_strategy"] = {
            "1. Read PE header from disk and parse Section Table (.text, .rdata, .data)",
            "2. Map section VirtualAddress and SizeOfRawData to target memory base",
            "3. Compute SHA256 of in-memory .text section vs relocated on-disk .text section",
            "4. Filter out benign modifications (relocation fixups, IAT resolution, runtime hooks)",
            "5. Flag wholesale code replacement (>20% byte divergence) as Module Stomping"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/module_stomp/detect_text_section_overwrites", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["stomping_variants"] = {
            {"Classic_Module_Stomping", "Direct overwrite of .text section of legitimate DLL"},
            {"Module_Overloading", "Unmapping original DLL sections and re-mapping custom PE headers"},
            {"GHOST_Hollowing", "Modifying .text before section mapping commit to evade EDR hooks"}
        };
        result["remediation"] = "Re-read original section from disk or compare against ntoskrnl page cache";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
