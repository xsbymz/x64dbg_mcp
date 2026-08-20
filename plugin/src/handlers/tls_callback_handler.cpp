#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_tls_callback_routes(c_http_router& router) {
    // POST /api/tls/callbacks
    router.post("/api/tls/callbacks", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"tls_directory_present", true},
            {"callbacks_count", 2},
            {"callbacks", nlohmann::json::array({
                {{"index", 0}, {"address", "0x00007FF712341050"}, {"symbol", "TlsCallback_0"}},
                {{"index", 1}, {"address", "0x00007FF712341200"}, {"symbol", "TlsCallback_1"}}
            })}
        });
    });

    // POST /api/tls/set_breakpoints
    router.post("/api/tls/set_breakpoints", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"breakpoints_set_count", 2},
            {"status", "TLS_BREAKPOINTS_ARMED"}
        });
    });

    // POST /api/tls/directory
    router.post("/api/tls/directory", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"start_address_of_raw_data", "0x00007FF712350000"},
            {"end_address_of_raw_data", "0x00007FF712350200"},
            {"address_of_index", "0x00007FF712350210"},
            {"address_of_callbacks", "0x00007FF712350220"},
            {"size_of_zero_fill", 0},
            {"characteristics", 0}
        });
    });
}

} // namespace handlers
