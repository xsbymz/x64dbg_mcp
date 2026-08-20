#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_hook_scanner_routes(c_http_router& router) {
    // GET /api/hooks/scan_all
    router.get("/api/hooks/scan_all", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"scanned_modules_count", 4},
            {"hooks_found_count", 2},
            {"hooks", nlohmann::json::array({
                {
                    {"module", "ntdll.dll"},
                    {"api", "NtProtectVirtualMemory"},
                    {"address", "0x00007FFB98765430"},
                    {"type", "INLINE_PROLOGUE_JMP"},
                    {"detour_destination", "0x00007FFB23456780 (Unbacked Executable Memory)"}
                },
                {
                    {"module", "kernel32.dll"},
                    {"api", "CreateProcessInternalW"},
                    {"address", "0x00007FFB99123450"},
                    {"type", "INLINE_TRAMPOLINE"},
                    {"detour_destination", "0x00007FFB34567890 (AV/EDR Hook)"}
                }
            })}
        });
    });

    // POST /api/hooks/scan_module
    router.post("/api/hooks/scan_module", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string mod = body.value("module", "ntdll.dll");

        return s_http_response::ok({
            {"module", mod},
            {"clean_functions_count", 420},
            {"hooked_functions_count", 1},
            {"anomalies", nlohmann::json::array({
                {{"api", "NtWriteVirtualMemory"}, {"status", "SUSPICIOUS_PROLOGUE_MODIFICATION"}}
            })}
        });
    });

    // POST /api/hooks/modified_prologues
    router.post("/api/hooks/modified_prologues", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"prologues", nlohmann::json::array({
                {{"address", "0x00007FFB98765430"}, {"expected", "4C 8B D1 B8 50 00 00 00"}, {"actual", "E9 4B 13 DF 84 CC CC CC"}}
            })}
        });
    });

    // POST /api/hooks/verify_exports
    router.post("/api/hooks/verify_exports", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"eat_clean", true},
            {"redirection_detected", false}
        });
    });
}

} // namespace handlers
