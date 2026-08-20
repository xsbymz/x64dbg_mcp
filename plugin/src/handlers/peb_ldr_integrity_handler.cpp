#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_peb_ldr_integrity_routes(c_http_router& router) {
    router.post("/api/peb_ldr/check_all_three_lists", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["peb_ldr_lists"] = {
            {"InLoadOrderModuleList", "Doubly-linked list ordered by module load sequence"},
            {"InMemoryOrderModuleList", "Doubly-linked list ordered by base memory address"},
            {"InInitializationOrderModuleList", "Doubly-linked list ordered by DllMain initialization order"}
        };
        result["integrity_rule"] = "Every loaded module MUST appear in all three doubly-linked lists. An unlinking attempt often modifies InLoadOrderModuleList but forgets InInitializationOrderModuleList, creating a partial unlink discrepancy.";
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/peb_ldr/detect_partial_unlink", [](const s_http_request& req) {
        json result;
        result["unlink_detection_strategy"] = {
            "1. Traverse InLoadOrderModuleList -> collect set of DllBase addresses",
            "2. Traverse InMemoryOrderModuleList -> collect set of DllBase addresses",
            "3. Traverse InInitializationOrderModuleList -> collect set of DllBase addresses",
            "4. Compute symmetric difference among the three sets — any disparity indicates stealth module unlinking"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/peb_ldr/cross_validate_module_lists", [](const s_http_request& req) {
        json result;
        result["cross_validation_sources"] = {
            "PEB.Ldr vs CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)",
            "PEB.Ldr vs EnumProcessModulesEx (PSAPI)",
            "PEB.Ldr vs VirtualQueryEx (MEM_IMAGE allocations in address space)",
            "PEB.Ldr vs Kernel PsLoadedModuleList"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

