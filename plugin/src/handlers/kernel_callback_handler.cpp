#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_kernel_callback_routes(c_http_router& router) {
    // POST /api/kernel_callbacks/process_thread
    router.post("/api/kernel_callbacks/process_thread", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"process_creation_callbacks", nlohmann::json::array({
                {{"index", 0}, {"driver", "WdFilter.sys"}, {"callback_routine", "0xFFFFF80010001234"}}
            })},
            {"thread_creation_callbacks", nlohmann::json::array({
                {{"index", 0}, {"driver", "cng.sys"}, {"callback_routine", "0xFFFFF80010005678"}}
            })},
            {"total_callbacks_registered", 2}
        });
    });

    // POST /api/kernel_callbacks/object_filters
    router.post("/api/kernel_callbacks/object_filters", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"ob_process_callbacks", nlohmann::json::array({
                {{"altitude", "320000"}, {"driver", "WdFilter.sys"}, {"stripped_access_mask", "0x1FFFFF"}}
            })},
            {"ob_thread_callbacks", nlohmann::json::array()}
        });
    });

    // POST /api/kernel_callbacks/minifilters
    router.post("/api/kernel_callbacks/minifilters", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"registered_minifilters", nlohmann::json::array({
                {{"name", "WdFilter"}, {"altitude", "328010"}, {"pre_operations", 12}, {"post_operations", 8}}
            })}
        });
    });
}

} // namespace handlers
