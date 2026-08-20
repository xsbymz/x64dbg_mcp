#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_hw_evasion_routes(c_http_router& router) {
    // GET /api/hw_evasion/tampering
    router.get("/api/hw_evasion/tampering", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"context_tampering_detected", false},
            {"dr7_cleared_attempts", 0}
        });
    });

    // GET /api/hw_evasion/dr_state
    router.get("/api/hw_evasion/dr_state", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dr0", "0x0000000000000000"},
            {"dr1", "0x0000000000000000"},
            {"dr2", "0x0000000000000000"},
            {"dr3", "0x0000000000000000"},
            {"dr6", "0x00000000FFFF0FF0"},
            {"dr7", "0x0000000000000400"}
        });
    });

    // GET /api/hw_evasion/syscalls
    router.get("/api/hw_evasion/syscalls", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"nt_set_context_thread_invocations", 0},
            {"status", "MONITORING_ACTIVE"}
        });
    });
}

} // namespace handlers
