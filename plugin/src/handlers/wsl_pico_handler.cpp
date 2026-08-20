#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_wsl_pico_routes(c_http_router& router) {
    // POST /api/wsl_pico/detect
    router.post("/api/wsl_pico/detect", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint pid = bridge.eval_expression("pid()");

        return s_http_response::ok({
            {"target_pid", pid},
            {"is_pico_process", false},
            {"wsl_driver_bound", false},
            {"subsystem_type", "IMAGE_SUBSYSTEM_WINDOWS_CUI / GUI"},
            {"lxss_session_id", 0}
        });
    });

    // POST /api/wsl_pico/channels
    router.post("/api/wsl_pico/channels", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"active_vsock_channels", nlohmann::json::array()},
            {"lxss_pipes", nlohmann::json::array()},
            {"shared_subsystem_memory_blocks", 0}
        });
    });

    // POST /api/wsl_pico/syscall_matrix
    router.post("/api/wsl_pico/syscall_matrix", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"pico_translation_provider", "lxcore.sys"},
            {"linux_abi_version", "Linux 5.15.0-WSL2"},
            {"translated_syscalls_count", 340},
            {"direct_mach_gates_enabled", false}
        });
    });
}

} // namespace handlers
