#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_cxx_throw_routes(c_http_router& router) {
    // POST /api/cxx_throw/parse
    router.post("/api/cxx_throw/parse", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"attributes", 0},
            {"pmfnUnwind", "0x00007FF712341050"},
            {"num_catchable_types", 1}
        });
    });

    // POST /api/cxx_throw/catchable_types
    router.post("/api/cxx_throw/catchable_types", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"types", nlohmann::json::array({
                {{"type_descriptor", ".?AVruntime_error@std@@"}, {"size", 32}}
            })}
        });
    });

    // POST /api/cxx_throw/active
    router.post("/api/cxx_throw/active", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"active_cxx_exception", true},
            {"exception_type", "std::runtime_error"}
        });
    });
}

} // namespace handlers
