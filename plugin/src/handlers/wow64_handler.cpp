#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_wow64_routes(c_http_router& router) {
    // GET /api/wow64/heavens_gate
    router.get("/api/wow64/heavens_gate", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_wow64", false},
            {"heavens_gate_detected", false},
            {"segment_selector_64", "0x0033"}
        });
    });

    // GET /api/wow64/cpu_state
    router.get("/api/wow64/cpu_state", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"mode", "NATIVE_X64"},
            {"cs", "0x0033"},
            {"ss", "0x002B"}
        });
    });

    // GET /api/wow64/teb64
    router.get("/api/wow64/teb64", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"teb64_address", "0x00007FF710000000"},
            {"peb64_address", "0x00007FF700000000"}
        });
    });
}

} // namespace handlers
