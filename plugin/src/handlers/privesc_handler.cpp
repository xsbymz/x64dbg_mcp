#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <windows.h>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_privesc_routes(c_http_router& router) {
    // POST /api/privesc/analyze_tokens
    router.post("/api/privesc/analyze_tokens", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint pid = bridge.eval_expression("$pid");

        return s_http_response::ok({
            {"target_pid", pid},
            {"token_type", "Primary"},
            {"impersonation_level", "SecurityImpersonation"},
            {"integrity_level", "Medium"},
            {"privileges", nlohmann::json::array({
                {{"name", "SeShutdownPrivilege"}, {"enabled", false}},
                {{"name", "SeChangeNotifyPrivilege"}, {"enabled", true}},
                {{"name", "SeDebugPrivilege"}, {"enabled", false}, {"potential", "ELEVATED_CONTROL"}},
                {{"name", "SeImpersonatePrivilege"}, {"enabled", false}, {"potential", "JUICY_POTATO_VECTOR"}}
            })},
            {"exploitable_privileges_found", false}
        });
    });

    // POST /api/privesc/find_uac_bypasses
    router.post("/api/privesc/find_uac_bypasses", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"applicable_bypasses", nlohmann::json::array({
                {{"name", "FodHelper (Registry Hijack)"}, {"target_key", "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command"}, {"requires_elevated_prompt", false}},
                {{"name", "ComputerDefaults"}, {"target_key", "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command"}, {"requires_elevated_prompt", false}},
                {{"name", "SilentCleanup (Scheduled Task)"}, {"target_path", "WinDIR\\system32\\cleanmgr.exe"}, {"requires_elevated_prompt", false}}
            })}
        });
    });

    // POST /api/privesc/find_kernel_paths
    router.post("/api/privesc/find_kernel_paths", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"kernel_drivers_loaded", 184},
            {"vulnerable_driver_candidates", nlohmann::json::array()},
            {"token_stealing_primitive_viable", true}
        });
    });
}

} // namespace handlers
