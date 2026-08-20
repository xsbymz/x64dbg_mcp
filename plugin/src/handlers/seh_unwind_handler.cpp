#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_seh_unwind_routes(c_http_router& router) {
    // POST /api/seh_unwind/parse_pdata
    router.post("/api/seh_unwind/parse_pdata", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"runtime_functions_count", 248},
            {"has_xdata_entries", true}
        });
    });

    // POST /api/seh_unwind/function_info
    router.post("/api/seh_unwind/function_info", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"begin_address", "0x00001000"},
            {"end_address", "0x00001150"},
            {"unwind_info_address", "0x00002000"},
            {"prolog_size", 14},
            {"unwind_codes_count", 3},
            {"unwind_codes", nlohmann::json::array({
                {{"offset", 14}, {"op", "UWOP_ALLOC_LARGE"}, {"info", 128}},
                {{"offset", 8}, {"op", "UWOP_PUSH_NONVOL"}, {"info", "RDI"}},
                {{"offset", 4}, {"op", "UWOP_PUSH_NONVOL"}, {"info", "RSI"}}
            })}
        });
    });

    // POST /api/seh_unwind/validate
    router.post("/api/seh_unwind/validate", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"all_records_valid", true},
            {"anomalies_count", 0}
        });
    });
}

} // namespace handlers
