#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_vmbus_inspector_routes(c_http_router& router) {
    // POST /api/vmbus/enum_channels
    router.post("/api/vmbus/enum_channels", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"hyperv_guest_detected", false},
            {"vmbus_channels", nlohmann::json::array()},
            {"synic_enabled", false}
        });
    });

    // POST /api/vmbus/inspect_hypercall_page
    router.post("/api/vmbus/inspect_hypercall_page", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"hypercall_msr_active", false},
            {"hypercall_page_address", "0x0"},
            {"enlightenment_status", "NOT_ENLIGHTENED"}
        });
    });
}

} // namespace handlers
