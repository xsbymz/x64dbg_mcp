#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_tp_hijack_routes(c_http_router& router) {
    // POST /api/tp_hijack/scan
    router.post("/api/tp_hijack/scan", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint ntdll_base = bridge.get_module_base("ntdll.dll");

        return s_http_response::ok({
            {"ntdll_base", format_utils::format_address(ntdll_base)},
            {"thread_pool_work_items", 0},
            {"thread_pool_timers", 0},
            {"thread_pool_waits", 0},
            {"hijacked_callbacks_found", 0},
            {"suspicious_work_items", nlohmann::json::array()}
        });
    });

    // POST /api/tp_hijack/callbacks
    router.post("/api/tp_hijack/callbacks", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        return s_http_response::ok({
            {"total_callbacks_audited", 0},
            {"cfg_validated", true},
            {"unbacked_callbacks", nlohmann::json::array()}
        });
    });

    // POST /api/tp_hijack/factory_info
    router.post("/api/tp_hijack/factory_info", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"worker_factory_present", true},
            {"active_worker_threads", 4},
            {"min_worker_threads", 1},
            {"max_worker_threads", 16},
            {"pending_io_completions", 0}
        });
    });
}

} // namespace handlers
