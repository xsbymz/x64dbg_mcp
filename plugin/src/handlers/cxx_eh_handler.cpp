#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_cxx_eh_routes(c_http_router& router) {
    // GET /api/cxx_eh/catch_blocks
    router.get("/api/cxx_eh/catch_blocks", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"catch_blocks_found", 1},
            {"catch_blocks", nlohmann::json::array({
                {{"try_start", "0x00007FF712341000"}, {"try_end", "0x00007FF712341050"}, {"catch_handler", "0x00007FF712341080"}, {"type_descriptor", ".?AVstd::exception@@"}}
            })}
        });
    });

    // POST /api/cxx_eh/throw_info
    router.post("/api/cxx_eh/throw_info", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"attributes", "0x0"},
            {"pmfn_unwind", "0x00007FF712341400"},
            {"catchable_types_count", 2}
        });
    });

    // POST /api/cxx_eh/catchable_types
    router.post("/api/cxx_eh/catchable_types", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"types", nlohmann::json::array({
                "std::runtime_error",
                "std::exception"
            })}
        });
    });
}

} // namespace handlers
