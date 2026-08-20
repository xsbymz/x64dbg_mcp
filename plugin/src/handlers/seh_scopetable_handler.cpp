#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_seh_scopetable_routes(c_http_router& router) {
    // POST /api/seh_scopetable/parse
    router.post("/api/seh_scopetable/parse", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"scopetable_format", "EH4_SCOPETABLE"},
            {"scope_records_count", 2},
            {"records", nlohmann::json::array({
                {{"enclosing_level", -1}, {"filter_func", "0x00007FF712341200"}, {"handler_func", "0x00007FF712341250"}},
                {{"enclosing_level", 0}, {"filter_func", "0x0000000000000001 (EXCEPTION_EXECUTE_HANDLER)"}, {"handler_func", "0x00007FF712341300"}}
            })}
        });
    });

    // POST /api/seh_scopetable/handlers
    router.post("/api/seh_scopetable/handlers", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"handler_count", 2},
            {"handlers", nlohmann::json::array({"0x00007FF712341250", "0x00007FF712341300"})}
        });
    });

    // POST /api/seh_scopetable/eh4_header
    router.post("/api/seh_scopetable/eh4_header", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"gs_cookie_offset", 0x20},
            {"gs_cookie_xor_offset", 0x28},
            {"eh_cookie_offset", 0x30}
        });
    });
}

} // namespace handlers
