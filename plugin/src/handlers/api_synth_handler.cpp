#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_api_synth_routes(c_http_router& router) {
    // POST /api/api_synth/simulate
    router.post("/api/api_synth/simulate", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string api = body.value("api_name", "kernel32.dll!GetCurrentProcessId");

        return s_http_response::ok({
            {"api_name", api},
            {"simulated_return_value_rax", "0x0000000000001024"},
            {"status", "API_EXECUTION_SIMULATED"}
        });
    });

    // GET /api/api_synth/supported
    router.get("/api/api_synth/supported", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"supported_calling_conventions", nlohmann::json::array({"__fastcall", "__cdecl", "__stdcall"})},
            {"max_simulated_args", 16}
        });
    });
}

} // namespace handlers
